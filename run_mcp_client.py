"""
run_mcp_client.py
-----------------
Demonstrates a proper MCP client connecting to our Gmail MCP server over stdio.

It spawns the server script (mcp-server/gmail_mcp_server.py) as a subprocess,
establishes an MCP session, lists the tools exposed by the server, and gracefully
handles execution of tools depending on whether Gmail credentials are configured.
"""

import asyncio
import os
import sys
from pathlib import Path
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PROJECT_ROOT = Path(__file__).resolve().parent
SERVER_SCRIPT = PROJECT_ROOT / "mcp-server" / "gmail_mcp_server.py"
CREDENTIALS_PATH = PROJECT_ROOT / "credentials.json"


async def main():
    print("=" * 60)
    print("Gmail MCP Client - stdio Connection Demo")
    print("=" * 60)

    # 1. Check if the server script exists
    if not SERVER_SCRIPT.exists():
        print(f"[ERROR] MCP Server script not found at: {SERVER_SCRIPT}")
        return

    # 2. Define the server launch parameters (spawn server script via python)
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(SERVER_SCRIPT)],
        env=os.environ.copy()
    )

    print(f"\n[Client] Launching MCP server: {sys.executable} {SERVER_SCRIPT.name} ...")

    # 3. Connect to the server using the stdio transport
    try:
        async with stdio_client(server_params) as (read_stream, write_stream):
            print("[Client] Stdio transport connection established.")
            
            # 4. Create and initialize the client session
            async with ClientSession(read_stream, write_stream) as session:
                print("[Client] Initializing session...")
                await session.initialize()
                print("[Client] Session initialized successfully.")

                # 5. List available tools on the server (Protocol check)
                print("\n[Client] Querying tools from server...")
                tools_response = await session.list_tools()
                
                print("\nExposed Tools list:")
                for tool in tools_response.tools:
                    print(f"  - Tool: {tool.name}")
                    print(f"    Description: {tool.description}")
                    print(f"    Schema: {tool.inputSchema}")
                    print()

                # 6. Attempt tool execution based on credentials availability
                if not CREDENTIALS_PATH.exists():
                    print("-" * 60)
                    print("[INFO] credentials.json is missing in the project root.")
                    print("To test live Gmail tool execution:")
                    print("  1. Download credentials.json from Google Cloud Console.")
                    print("  2. Place it in the project root folder.")
                    print("  3. Run this script again to prompt the browser OAuth flow.")
                    print("-" * 60)
                else:
                    print("\n[Client] credentials.json detected. Querying list_messages tool...")
                    try:
                        result = await session.call_tool("list_messages", arguments={"max_results": 3})
                        print(f"Tool Result content:\n{result.content}")
                    except Exception as err:
                        print(f"[WARNING] Tool execution failed: {err}")

    except Exception as exc:
        print(f"[ERROR] Failed to run MCP Client session: {exc}")
        print("\nEnsure you have installed all dependencies in requirements.txt")

    print("\n" + "=" * 60)
    print("MCP Client connection demo completed.")
    print("=" * 60)


if __name__ == "__main__":
    # FIX Bug 15: WindowsProactorEventLoopPolicy can conflict with stdio
    # subprocess I/O used by the MCP stdio transport.
    # WindowsSelectorEventLoopPolicy is safer for subprocess-heavy async code.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
