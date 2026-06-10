import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// The localization messages are located in 'messages' directory
const messagesDir = path.resolve(__dirname, "../messages");
const zhPath = path.join(messagesDir, "zh.json");
const enPath = path.join(messagesDir, "en.json");
const zhHantPath = path.join(messagesDir, "zh-Hant.json");

try {
  const zhContent = JSON.parse(fs.readFileSync(zhPath, "utf8"));
  const enContent = JSON.parse(fs.readFileSync(enPath, "utf8"));
  const zhHantContent = JSON.parse(fs.readFileSync(zhHantPath, "utf8"));

  // Get keys from source language file, excluding the schema property
  const zhKeys = Object.keys(zhContent).filter((k) => k !== "$schema");

  let hasError = false;

  // Find which ones are missing in the target language files
  const missingEnKeys = zhKeys.filter((key) => !(key in enContent));
  if (missingEnKeys.length > 0) {
    console.error(
      `❌ Found ${missingEnKeys.length} missing translation keys in en.json:`,
    );
    missingEnKeys.forEach((key) => {
      console.error(`  - ${key}`);
    });
    hasError = true;
  }

  const missingZhHantKeys = zhKeys.filter((key) => !(key in zhHantContent));
  if (missingZhHantKeys.length > 0) {
    console.error(
      `❌ Found ${missingZhHantKeys.length} missing translation keys in zh-Hant.json:`,
    );
    missingZhHantKeys.forEach((key) => {
      console.error(`  - ${key}`);
    });
    hasError = true;
  }

  if (!hasError) {
    console.log(
      "✅ Translation verification passed: All keys from zh.json are present in en.json and zh-Hant.json.",
    );
  } else {
    process.exit(1);
  }
} catch (error) {
  console.error("❌ Error verifying translations:", error);
  process.exit(1);
}
