from functools import lru_cache

from llama_cpp import Llama

MODEL_REPO_ID = "unsloth/gemma-4-E2B-it-GGUF"
MODEL_FILENAME = "*Q8_0.gguf"
DEFAULT_SYSTEM_PROMPT = "당신은 유능하고 친절한 AI 어시스턴트입니다."
DEFAULT_N_CTX = 4096
DEFAULT_MAX_TOKENS = 500
DEFAULT_TEMPERATURE = 0.7


@lru_cache(maxsize=1)
def get_model() -> Llama:
    """Load Gemma once and reuse it across parser-generation requests."""
    return Llama.from_pretrained(
        repo_id=MODEL_REPO_ID,
        filename=MODEL_FILENAME,
        n_ctx=DEFAULT_N_CTX,
        n_gpu_layers=-1,
        verbose=False,
    )


def generate_response(
    prompt: str,
    *,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    temperature: float = DEFAULT_TEMPERATURE,
) -> str:
    output = get_model().create_chat_completion(
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        max_tokens=max_tokens,
        temperature=temperature,
    )
    return output["choices"][0]["message"]["content"]


if __name__ == "__main__":
    prompt = "Gemma 4의 주요 특징 세 가지만 알려줘."
    response = generate_response(prompt)
    print(f"답변: {response}")
