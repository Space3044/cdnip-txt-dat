#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');
const { isIP } = require('node:net');

function printUsage() {
  console.log([
    '用法:',
    '  node build_geoip_dat.js [输入文件] [输出文件] [列表名]',
    '',
    '默认值:',
    '  输入文件: ./cdnip.txt',
    '  输出文件: ./geoip.dat',
    '  列表名:   cdnip',
    '',
    '示例:',
    '  node build_geoip_dat.js',
    '  node build_geoip_dat.js @cdnip.txt ./geoip.dat cdnip',
  ].join('\n'));
}

function encodeVarint(value) {
  let current = BigInt(value);
  if (current < 0n) {
    throw new Error(`不支持负数 varint: ${value}`);
  }

  const bytes = [];
  do {
    let byte = Number(current & 0x7fn);
    current >>= 7n;
    if (current > 0n) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (current > 0n);

  return Buffer.from(bytes);
}

function encodeBytesField(fieldNumber, payload) {
  return Buffer.concat([
    encodeVarint((fieldNumber << 3) | 2),
    encodeVarint(payload.length),
    payload,
  ]);
}

function encodeVarintField(fieldNumber, value) {
  return Buffer.concat([
    encodeVarint(fieldNumber << 3),
    encodeVarint(value),
  ]);
}

function parseIPv4(address) {
  const parts = address.split('.');
  if (parts.length !== 4) {
    throw new Error(`非法 IPv4 地址: ${address}`);
  }

  const bytes = parts.map((part) => {
    if (!/^\d+$/.test(part)) {
      throw new Error(`非法 IPv4 地址: ${address}`);
    }

    const value = Number(part);
    if (value < 0 || value > 255) {
      throw new Error(`非法 IPv4 地址: ${address}`);
    }
    return value;
  });

  return Buffer.from(bytes);
}

function parseIPv6(address) {
  const normalized = address.split('%')[0].toLowerCase();
  if (!normalized) {
    throw new Error(`非法 IPv6 地址: ${address}`);
  }

  const doubleColonCount = (normalized.match(/::/g) || []).length;
  if (doubleColonCount > 1) {
    throw new Error(`非法 IPv6 地址: ${address}`);
  }

  const [leftPart, rightPart = ''] = normalized.split('::');
  const left = expandIPv6Segments(leftPart);
  const right = doubleColonCount === 1 ? expandIPv6Segments(rightPart) : [];

  let segments = [];
  if (doubleColonCount === 1) {
    const missing = 8 - (left.length + right.length);
    if (missing < 1) {
      throw new Error(`非法 IPv6 地址: ${address}`);
    }
    segments = [...left, ...Array(missing).fill(0), ...right];
  } else {
    segments = left;
    if (segments.length !== 8) {
      throw new Error(`非法 IPv6 地址: ${address}`);
    }
  }

  if (segments.length !== 8) {
    throw new Error(`非法 IPv6 地址: ${address}`);
  }

  const buffer = Buffer.alloc(16);
  for (let index = 0; index < segments.length; index += 1) {
    buffer.writeUInt16BE(segments[index], index * 2);
  }
  return buffer;
}

function expandIPv6Segments(part) {
  if (!part) {
    return [];
  }

  return part.split(':').flatMap((segment) => {
    if (!segment) {
      throw new Error(`非法 IPv6 段: ${part}`);
    }

    if (segment.includes('.')) {
      const ipv4 = parseIPv4(segment);
      return [
        (ipv4[0] << 8) | ipv4[1],
        (ipv4[2] << 8) | ipv4[3],
      ];
    }

    if (!/^[0-9a-f]{1,4}$/.test(segment)) {
      throw new Error(`非法 IPv6 段: ${part}`);
    }

    return [Number.parseInt(segment, 16)];
  });
}

function parseIp(address) {
  const family = isIP(address);
  if (family === 4) {
    return { family, buffer: parseIPv4(address) };
  }
  if (family === 6) {
    return { family, buffer: parseIPv6(address) };
  }
  throw new Error(`非法 IP 地址: ${address}`);
}

function maskIp(buffer, prefixBits) {
  const output = Buffer.from(buffer);
  let bitsLeft = prefixBits;

  for (let index = 0; index < output.length; index += 1) {
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      continue;
    }

    if (bitsLeft <= 0) {
      output[index] = 0;
      continue;
    }

    const mask = (0xff << (8 - bitsLeft)) & 0xff;
    output[index] &= mask;
    bitsLeft = 0;
  }

  return output;
}

function parseLine(rawLine, lineNumber) {
  const cleaned = rawLine.replace(/\s*(#|\/\/).*$/, '').trim();
  if (!cleaned) {
    return null;
  }

  const [ipPart, prefixPart] = cleaned.split('/');
  if (!ipPart) {
    throw new Error(`第 ${lineNumber} 行格式无效: ${rawLine}`);
  }

  const parsedIp = parseIp(ipPart.trim());
  const maxPrefix = parsedIp.family === 4 ? 32 : 128;
  const prefix = prefixPart === undefined || prefixPart === ''
    ? maxPrefix
    : Number.parseInt(prefixPart, 10);

  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    throw new Error(`第 ${lineNumber} 行前缀无效: ${rawLine}`);
  }

  return {
    ip: maskIp(parsedIp.buffer, prefix),
    prefix,
  };
}

function buildCidrMessage(entry) {
  return Buffer.concat([
    encodeBytesField(1, entry.ip),
    encodeVarintField(2, entry.prefix),
  ]);
}

function buildGeoIpMessage(name, cidrEntries) {
  const parts = [encodeBytesField(1, Buffer.from(name, 'utf8'))];
  for (const cidr of cidrEntries) {
    parts.push(encodeBytesField(2, buildCidrMessage(cidr)));
  }
  return Buffer.concat(parts);
}

function buildGeoIpListMessage(name, cidrEntries) {
  return encodeBytesField(1, buildGeoIpMessage(name, cidrEntries));
}

function uniqueEntries(entries) {
  const deduplicated = [];
  const seen = new Set();

  for (const entry of entries) {
    const key = `${entry.ip.toString('hex')}/${entry.prefix}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    deduplicated.push(entry);
  }

  return deduplicated;
}

function resolveInputPath(inputArg) {
  const normalized = inputArg.startsWith('@') ? inputArg.slice(1) : inputArg;
  return path.resolve(normalized);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('-h') || args.includes('--help')) {
    printUsage();
    return;
  }

  const inputPath = resolveInputPath(args[0] || './cdnip.txt');
  const outputPath = path.resolve(args[1] || './geoip.dat');
  const listName = (args[2] || 'cdnip').trim().toUpperCase();

  if (!listName) {
    throw new Error('列表名不能为空。');
  }

  const content = fs.readFileSync(inputPath, 'utf8');
  const lines = content.split(/\r?\n/);
  const entries = [];

  for (let index = 0; index < lines.length; index += 1) {
    const parsed = parseLine(lines[index], index + 1);
    if (parsed) {
      entries.push(parsed);
    }
  }

  const finalEntries = uniqueEntries(entries);
  if (finalEntries.length === 0) {
    throw new Error('没有读取到任何有效的 IP/CIDR。');
  }

  const output = buildGeoIpListMessage(listName, finalEntries);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, output);

  console.log(`已生成 ${outputPath}`);
  console.log(`列表名: ${listName}`);
  console.log(`CIDR 数量: ${finalEntries.length}`);
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
