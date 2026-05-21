from fastapi import FastAPI
from strawberry.fastapi import GraphQLRouter

from schema import schema

app = FastAPI()
graphql_app = GraphQLRouter(schema, path="/graphql")
app.include_router(graphql_app)

@app.get("/health")
def health():
    return {"status": "ok"}