#!/usr/bin/env node
import { main } from '../src/cli/index.mjs';

main(process.argv.slice(2)).catch((e) => {
  console.error(`\n  ${process.stdout.isTTY ? '\x1b[31m✖\x1b[39m' : '[x]'} ${e.message}\n`);
  if (process.env.STAFFET_DEBUG) console.error(e.stack);
  process.exit(1);
});
