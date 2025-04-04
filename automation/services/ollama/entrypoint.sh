#!/bin/bash

# Start Ollama in the background.
/bin/ollama serve &
# Record Process ID.
pid=$!

# Pause for Ollama to start.
sleep 5

MODELS="llama3.3 phi4 nomic-embed-text llava llama3-groq-tool-use"

for model in ${MODELS}; do
    echo "🔴 Retrieve ${model^^} model..."
    ollama pull ${model}
    echo "🟢 Done!"
done

# Wait for Ollama process to finish.
wait $pid
