import type { Orama, Tokenizer } from "@orama/orama";
import { create } from "@orama/orama";

function getSegmenter(locale = "zh") {
  const tag = locale === "zh-Hant" ? "zh-TW" : "zh-CN";
  return new Intl.Segmenter(tag, { granularity: "word" });
}

export function createTokenizer(locale = "zh"): Tokenizer {
  const segmenter = getSegmenter(locale);
  return {
    language: "chinese",
    tokenize: (text: string) => {
      return Array.from(segmenter.segment(text))
        .filter((x) => x.isWordLike)
        .map((x) => x.segment.toLowerCase());
    },
    normalizationCache: new Map(),
  };
}

export const chineseTokenizerConfig: Tokenizer = createTokenizer();

export const searchSchema = {
  id: "string",
  slug: "string",
  title: "string",
  summary: "string",
  content: "string",
  tags: "string[]",
} as const;

export type MyOramaDB = Orama<typeof searchSchema>;

export async function createMyDb(locale?: string) {
  return await create({
    schema: searchSchema,
    components: {
      tokenizer: locale ? createTokenizer(locale) : chineseTokenizerConfig,
    },
  });
}
