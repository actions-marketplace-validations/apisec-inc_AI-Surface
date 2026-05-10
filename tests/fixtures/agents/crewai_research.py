"""Synthetic CrewAI fixture: a researcher agent with search + email tools."""
from crewai import Agent, Crew, Task

search_tool = object()
send_email_tool = object()

researcher = Agent(
    role="researcher",
    goal="Investigate customer complaints",
    backstory="An AI research analyst.",
    tools=[search_tool, send_email_tool],
    verbose=True,
)

task = Task(description="Investigate ticket #123", agent=researcher)
crew = Crew(agents=[researcher], tasks=[task])
