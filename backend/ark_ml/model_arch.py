"""
ARK Mythos 7B — Model Architecture Configuration.

This defines the architectural scaffolding for the Mythos 7B model, specifically
optimized for deep security reasoning, code analysis, and long-context trace logic.

Following the advanced specifications:
- 7B parameters (optimized for rapid iteration before scaling to 13B/70B)
- Grouped Query Attention (GQA) for efficient long-context inference (8 KV, 32 Q heads)
- SwiGLU activation in FFN elements (improves code/reasoning logic over ReLU)
- RMSNorm (Pre-norm) for training stability in long runs
- RoPE (Rotary Position Embeddings) extended to 32k natively for multi-file contexts
- Deeper, narrower architecture optimized for step-by-step logic chaining
"""

import os
from dataclasses import dataclass
from typing import Optional

try:
    from transformers import PretrainedConfig
except ImportError:
    # Fallback dummy class if transformers is not installed in the current env
    class PretrainedConfig:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)


@dataclass
class Mythos7BConfig(PretrainedConfig):
    """Configuration class for the Custom ARK Mythos Model."""
    
    model_type: str = "mythos"
    
    # Vocabulary (Expanded for 65k BPE + custom hex/ASM/security tokens)
    vocab_size: int = 65536
    
    # Hidden dimension & Layers (Depth over Width for complex logic reasoning)
    hidden_size: int = 4096
    intermediate_size: int = 11008  # Typically 8/3 * hidden_size for SwiGLU 
    num_hidden_layers: int = 48     # 48 layers (deeper than Llama 2 7B's 32)
    
    # Attention Heads (GQA specifics)
    num_attention_heads: int = 32
    num_key_value_heads: int = 8    # 8 KV heads -> Grouped Query Attention
    
    # Activations & Normalization
    hidden_act: str = "silu"        # Used for SwiGLU
    rms_norm_eps: float = 1e-6      # RMSNorm epsilon
    
    # Context Length & Positional Encoding
    max_position_embeddings: int = 32768  # Native 32k context size
    rope_theta: float = 1000000.0         # RoPE scaling base (critical for 32k+)
    
    # Precision
    torch_dtype: str = "bfloat16"         # bf16 for pre-training stability
    
    # Custom Security Tokens 
    bos_token_id: int = 1
    eos_token_id: int = 2
    pad_token_id: int = 0
    vuln_token_id: int = 65530      # <|vuln|>
    safe_token_id: int = 65531      # <|safe|>
    patch_token_id: int = 65532     # <|patch|>
    asm_token_id: int = 65533       # <|asm|>

    def __init__(self, **kwargs):
        super().__init__(**kwargs)


def get_mythos_training_args(output_dir: str = "./run/mythos-7b"):
    """
    Returns the recommended DeepSpeed / PyTorch arguments for pre-training
    the 7B model using the exact optimizer settings required for security reasoning.
    """
    return {
        "output_dir": output_dir,
        "optim": "adamw_torch",
        "adam_beta1": 0.9,
        "adam_beta2": 0.95,
        "weight_decay": 0.1,
        "max_grad_norm": 1.0,         # Gradient clipping
        "learning_rate": 3e-4,
        "warmup_steps": 2000,         # Minimum 2000 warmup steps
        "lr_scheduler_type": "cosine",
        # Important: Don't let LR drop below 3e-5 (min_lr equivalent in some schedulers)
        "bf16": True,
        "fp16": False,                # Force bf16 for stability
        "per_device_train_batch_size": 4,
        "gradient_accumulation_steps": 8,
        "gradient_checkpointing": True,
        # ZeRO-3 FSDP is recommended to be passed via deepspeed JSON config
    }

if __name__ == "__main__":
    # Test initialization
    config = Mythos7BConfig()
    print(f"Instantiated Mythos7B Config: {config.num_hidden_layers} layers, {config.hidden_size} hidden dim")
    print(f"Context size: {config.max_position_embeddings}")
    print(f"GQA configuration: {config.num_attention_heads} Query Heads, {config.num_key_value_heads} KV Heads")
