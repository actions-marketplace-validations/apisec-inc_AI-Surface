// Fixture: Claude Agent SDK (TypeScript). Not real app code.
import { ClaudeSDKClient, tool } from "@anthropic-ai/claude-agent-sdk";

const transferFunds = tool({ name: "transfer_funds", description: "move money" });

const client = new ClaudeSDKClient({ tools: [transferFunds] });

export { client };
