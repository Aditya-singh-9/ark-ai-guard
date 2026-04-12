"""
Setup script to download the offline AI model for ARK Mythos Tier 1 Engine.
Downloads a lightweight, high-performance Qwen1.5 0.5B model (~400MB) to act
as the baseline local generative AI reasoning module.
"""
import os
import sys

def download_model():
    # Use standard library to minimize dependencies before pip install
    import urllib.request
    
    url = "https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
    
    # Store where mythos_engine expects it
    dest_path = os.path.join(os.path.dirname(__file__), "mythos-7b-v1.gguf")
    
    if os.path.exists(dest_path):
        print(f"✅ Model already exists at {dest_path}")
        return

    print(f"📥 Downloading Mythos Baseline AI Model...")
    print(f"   URL: {url}")
    print(f"   Destination: {dest_path}")
    print("\n   Grab a coffee, this is roughly a 398MB download...")

    def progress(block_num, block_size, total_size):
        downloaded = block_num * block_size
        if total_size > 0:
            percent = downloaded * 100 / total_size
            sys.stdout.write(f"\r⏳ Progress: {percent:.1f}% ({downloaded / (1024*1024):.1f} MB / {total_size / (1024*1024):.1f} MB)")
            sys.stdout.flush()

    try:
        urllib.request.urlretrieve(url, dest_path, progress)
        print("\n\n🎉 Download complete! Tier 1 Mythos Deep Reasoning is now OFFLINE capable.")
    except Exception as e:
        print(f"\n❌ Download failed: {e}")
        if os.path.exists(dest_path):
            os.remove(dest_path)

if __name__ == "__main__":
    download_model()
