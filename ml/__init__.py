"""Fine-tuning pipeline: dataset curation, QLoRA training, eval, export.

See ml/README.md. Only curate_dataset.py runs without GPU/ML deps; the
rest import torch/transformers/peft/trl lazily and run on a GPU box.
"""
