// Synthetic fixture: Anthropic SDK in TypeScript.
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic();

export async function ask(prompt: string): Promise<string> {
  const message = await client.messages.create({
    model: "claude-3-5-haiku-20241022",
    max_tokens: 256,
    messages: [{ role: "user", content: prompt }],
  });
  return message.content[0].type === "text" ? message.content[0].text : "";
}
