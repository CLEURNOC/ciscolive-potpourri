#!/usr/bin/env python
from typing import Tuple
import sys
from langchain_community.document_loaders import UnstructuredPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores.chroma import Chroma
from langchain_community.chat_models import ChatOllama
from langchain.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from langchain.retrievers.multi_query import MultiQueryRetriever

COLLECTION_NAME = "kbyg-rag"
CHROMA_PATH = "/home/jclarke/kbyg-chroma"

KBYG_FILE = "/home/jclarke/kbyg.pdf"

EMBEDDING_MODEL = "nomic-embed-text"
MODEL = "llama3.3"


def get_vector_db() -> Chroma:
    # llama_auth = base64.b64encode(f"{CLEUCreds.LLAMA_USER}:{CLEUCreds.LLAMA_PASSWORD}".encode("utf-8"))
    # print(llama_auth)
    embedding = OllamaEmbeddings(model=EMBEDDING_MODEL, show_progress=True)

    db = Chroma(collection_name=COLLECTION_NAME, persist_directory=CHROMA_PATH, embedding_function=embedding)

    return db


def load_and_split_data(file: str) -> list:
    """Load the PDF and split it."""
    loader = UnstructuredPDFLoader(file_path=file)
    data = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=7500, chunk_overlap=100)
    chunks = text_splitter.split_documents(data)

    return chunks


def embed(file: str) -> None:
    """Load and split the file, and then add the chunks to the vector DB."""
    chunks = load_and_split_data(file)
    db = get_vector_db()
    db.add_documents(chunks)
    db.persist()


def get_prompt() -> Tuple[PromptTemplate, PromptTemplate]:
    """Get the prompts for the AI."""
    QUERY_PROMPT = PromptTemplate(
        input_variables=["question"],
        template="""You are an AI language model assistant versed in the CiscoLive Know Before You Go. Your task is to generate five
        different versions of the given user question to retrieve relevant documents from
        a vector database. By generating multiple perspectives on the user question, your
        goal is to help the user overcome some of the limitations of the distance-based
        similarity search. Provide these alternative questions separated by newlines.
        Original question: {question}""",
    )

    template = """Answer the question based ONLY on the following context.  Your response should be
    in markdown format.  Feel free to use emojis where and if appropriate:
    {context}
    Question: {question}
    """

    prompt = ChatPromptTemplate.from_template(template)

    return (QUERY_PROMPT, prompt)


def handle_message(msg: str) -> None:
    llm = ChatOllama(model=MODEL)
    db = get_vector_db()

    QUERY_PROMPT, prompt = get_prompt()

    retriever = MultiQueryRetriever.from_llm(db.as_retriever(), llm, prompt=QUERY_PROMPT)

    chain = {"context": retriever, "question": RunnablePassthrough()} | prompt | llm | StrOutputParser()

    response = chain.invoke(msg)

    print(response)


if __name__ == "__main__":
    if sys.argv[1] == "embed":
        embed(KBYG_FILE)
        exit(0)

    handle_message(" ".join(sys.argv[1:]))
