import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";

export async function run(q: string) {
  return generateText({
    model: openai("gpt-4o"),
    tools: {
      processRefund: tool({ description: "refund an order" }),
      lookupOrder: tool({ description: "look up an order" }),
    },
  });
}
