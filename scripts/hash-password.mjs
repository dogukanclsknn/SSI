#!/usr/bin/env node
// Lokal admin şifresi için scrypt hash üretir. Şifre stdin'den okunur
// (komut geçmişinde/argümanda görünmez). Çıktı hash'i SSI_LOCAL_ADMIN_PASSWORD_HASH
// olarak .env'e yazılır.
//
// Kullanım:
//   node scripts/hash-password.mjs
//   (şifreyi yazıp Enter'a basın; hash stdout'a yazılır)
//
// veya boru ile:
//   printf '%s' 'sifre' | node scripts/hash-password.mjs

import readline from 'node:readline';
import { hashPassword } from '../src/server/localAdmin.js';

function emit(password) {
  const value = String(password).replace(/\r?\n$/, '');
  if (!value) {
    process.stderr.write('Empty password — exiting.\n');
    process.exit(1);
  }
  process.stdout.write(`${hashPassword(value)}\n`);
}

if (process.stdin.isTTY) {
  process.stderr.write('Local admin password: ');
}

const rl = readline.createInterface({ input: process.stdin });
let handled = false;
rl.on('line', (line) => {
  if (handled) return;
  handled = true;
  emit(line);
  rl.close();
});
rl.on('close', () => {
  if (!handled) process.exit(1);
});
