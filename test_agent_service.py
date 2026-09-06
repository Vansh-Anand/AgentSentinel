import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath("."))
from dashboard_api.services.agent_service import AgentService

def main():
    service = AgentService()
    agent_resp, pipeline_res = service.process_chat("Read the demo report file.")
    print("Agent Response:")
    print(agent_resp)
    print("\nPipeline Result:")
    print(pipeline_res)

if __name__ == "__main__":
    main()
