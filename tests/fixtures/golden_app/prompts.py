from langchain_core.prompts import ChatPromptTemplate

SUPPORT_TEMPLATE = (
    "You are support. Customer email: {customer_email}, address: {customer_address}."
)
PROMPT = ChatPromptTemplate.from_messages([("system", SUPPORT_TEMPLATE), ("human", "{input}")])
