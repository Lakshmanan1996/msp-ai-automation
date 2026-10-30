import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():

    server_params = StdioServerParameters(
        command="python",
        args=["/opt/msp-ai/mcp_server.py"],
    )

    async with stdio_client(server_params) as (read, write):

        async with ClientSession(read, write) as session:

            await session.initialize()

            print("\n===== AVAILABLE MCP TOOLS =====")

            tools = await session.list_tools()

            for tool in tools.tools:
                print(f"- {tool.name}")
                print(f"  {tool.description}")
                print()

            print("\n===== CALLING MCP TOOL =====")

            result = await session.call_tool(
                "run_investigation",
                {
                    "machine": "EC2AMAZ-JEANI4A",
                    "customer": "Demo-Customer",
                    "site": "AWS-Windows-Lab",
                    "service_level": "DNOC.SRV.Manage",
                    "alert_time": "2026-09-29 15:30:10"
                }
            )

            for content in result.content:

                if hasattr(content, "text"):
                    print(content.text)


if __name__ == "__main__":
    asyncio.run(main())
