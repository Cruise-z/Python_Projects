# generation phase

# for humaneval
task="humaneval"
max_len=512
batch_size=20
top_p=0.95
n_sample=40

# for mbpp
task="mbpp"
max_len=2048
batch_size=5
top_p=0.95
n_sample=20

# for ds1000
task="ds1000-all-completion"
max_len=1024
batch_size=10
top_p=0.5
n_sample=40

# for projectDev
task="projectDev"
max_len=8192
batch_size=10
top_p=0.5
n_sample=40

GAMMA=0.5
DELTA=0.1
ENTROPY_THRESHOLD=0.9

accelerate launch --num_processes=1 main.py \
    --model bigcode/starcoder \
    --use_auth_token \
    --task $task \
    --temperature 0.2 \
    --precision bf16 \
    --batch_size $batch_size \
    --allow_code_execution \
    --do_sample \
    --top_p $top_p \
    --n_samples $n_sample \
    --max_length_generation $max_len \
    --save_references  \
    --save_generations \
    --outputs_dir /home/zhaorz/project/CodeWM/sweet-watermark/results_generation \
    --wllm \
    --gamma $GAMMA \
    --delta $DELTA \
    # --generation_only