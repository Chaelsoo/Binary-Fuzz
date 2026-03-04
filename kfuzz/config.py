from dataclasses import dataclass, field


@dataclass
class FuzzerConfig:
    target:       str
    input_dir:    str
    output_dir:   str
    timeout_ms:   int   = 1000
    memory_mb:    int   = 256
    qemu_mode:    bool  = False
    max_time:     int   = 0     # seconds; 0 = unlimited
    max_execs:    int   = 0     # 0 = unlimited
    map_size:     int   = 65536
    mutations_per_round: int = 16
