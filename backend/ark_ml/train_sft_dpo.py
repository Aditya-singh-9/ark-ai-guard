"""
ARK Mythos 7B — Alignment & Supervised Fine-Tuning Pipeline.

Contains scaffolding for:
1. SFT (Supervised Fine Tuning): Training the model to respond in a security reasoning format.
2. DPO (Direct Preference Optimization): Teaching the model *how* to reason about 
   exploits correctly, rewarding verifiable reasoning traces over hallucinated CVEs.
"""

import os

try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
    from peft import LoraConfig, get_peft_model
    from datasets import load_dataset
    from trl import SFTTrainer, DPOTrainer
except ImportError:
    pass

def load_mythos_model_and_tokenizer(model_path: str):
    """Loads base pre-trained Mythos 7B on bf16 with Flash Attention 2."""
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(
        model_path,
        torch_dtype=torch.bfloat16,
        attn_implementation="flash_attention_2",  # Crucial for long context (kernel source)
        device_map="auto"
    )
    return model, tokenizer

def run_sft(model_path: str, dataset_path: str, output_dir: str):
    """
    Supervised Fine-Tuning (SFT) phase using LoRA.
    Dataset should be instruction formatted pairs:
    [system] You are a vulnerability researcher...
    [user] Find memory safety bugs in this C function...
    [assistant] Line 47: stack buffer overflow...
    """
    print(f"Loading Base Mythos Model from {model_path} for SFT...")
    model, tokenizer = load_mythos_model_and_tokenizer(model_path)
    dataset = load_dataset("json", data_files=dataset_path, split="train")

    # Lower LR for fine-tuning as requested (1e-5 to 3e-5)
    training_args = TrainingArguments(
        output_dir=output_dir,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        learning_rate=2e-5,          
        num_train_epochs=3,          # 2-3 epochs max for SFT
        bf16=True,
        logging_steps=10,
        optim="adamw_torch",
        lr_scheduler_type="cosine",
        report_to="wandb"
    )

    # Use LoRA to preserve pre-trained knowledge while saving VRAM
    peft_config = LoraConfig(
        r=64,
        lora_alpha=128,
        # Target attention and mlp blocks specific to Llama/Mythos architecture
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        bias="none",
        task_type="CAUSAL_LM",
    )

    trainer = SFTTrainer(
        model=model,
        train_dataset=dataset,
        peft_config=peft_config,
        dataset_text_field="text",
        max_seq_length=4096,         # SFT sequence length
        tokenizer=tokenizer,
        args=training_args,
    )
    
    print("Beginning SFT Training...")
    trainer.train()
    trainer.save_model(os.path.join(output_dir, "mythos-sft-final"))
    print("SFT Complete.")

def run_dpo(sft_model_path: str, preference_dataset_path: str, output_dir: str):
    """
    Direct Preference Optimization (DPO).
    Teaches the model to prioritize detailed reasoning traces (memory layout,
    gadget discovery) and penalizes hallucinated/fake CVEs and non-functional shellcode.
    """
    print(f"Loading SFT Mythos Model for DPO Alignment from {sft_model_path}...")
    model, tokenizer = load_mythos_model_and_tokenizer(sft_model_path)
    
    # Reference model is simply the frozen SFT model
    ref_model, _ = load_mythos_model_and_tokenizer(sft_model_path)

    # Dataset must have columns: ['prompt', 'chosen', 'rejected']
    dataset = load_dataset("json", data_files=preference_dataset_path, split="train")

    training_args = TrainingArguments(
        output_dir=output_dir,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=8,
        learning_rate=5e-6,          # Extremely low LR for DPO
        num_train_epochs=1,
        bf16=True,
        logging_steps=10,
        report_to="wandb"
    )

    peft_config = LoraConfig(
        r=64, lora_alpha=128,
        target_modules=["q_proj", "v_proj"],
        task_type="CAUSAL_LM"
    )

    dpo_trainer = DPOTrainer(
        model,
        ref_model,
        args=training_args,
        beta=0.1,                    # DPO temperature parameter
        train_dataset=dataset,
        tokenizer=tokenizer,
        peft_config=peft_config,
        max_prompt_length=2048,
        max_length=4096,
    )

    print("Beginning DPO Alignment...")
    dpo_trainer.train()
    dpo_trainer.save_model(os.path.join(output_dir, "mythos-dpo-final"))
    print("DPO Complete. Model is aligned.")

if __name__ == "__main__":
    print("Mythos SFT & DPO Scaffolding ready. Execute functions directly via notebook or wrapper script.")
