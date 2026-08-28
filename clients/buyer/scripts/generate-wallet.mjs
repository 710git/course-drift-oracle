#!/usr/bin/env node
// Generates one throwaway EVM keypair and prints it. Used by
// the README ("Wiring a real x402 payer") to create a Base Sepolia TESTNET wallet
// for the buyer client's x402 payer (BUYER_PRIVATE_KEY).
//
// This key is disposable by design:
//   - never fund it with anything but testnet ETH/USDC
//   - never reuse it for anything else, ever
//   - the private key is printed to your terminal ONCE and nowhere else -
//     this script does not write it to any file, and you should not paste
//     it into a chat, an issue, a commit, or any file in this repo
//
// Usage: node scripts/generate-wallet.mjs

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const privateKey = generatePrivateKey();
const address = privateKeyToAccount(privateKey).address;

console.log("Generated a new throwaway Base Sepolia TESTNET keypair.");
console.log("");
console.log(`address:      ${address}`);
console.log(`private key:  ${privateKey}`);
console.log("");
console.log("This key is a testnet throwaway. Never send it real funds, never reuse");
console.log("it elsewhere, never paste it into chat or commit it to any file.");
console.log("Copy the private key into your shell's BUYER_PRIVATE_KEY variable now -");
console.log("it will not be shown again by this script.");
