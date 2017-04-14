# libdpf

A template for 2-server 1-bit Distributed Point Function. The construction is from "Function Secret Sharing: Improvements and Extensions" from Boyle et al. 

Please following this link for original publication in CCS'16:
https://cs.idc.ac.il/~elette/FSS-CCS.pdf

And the homepage of the first author Elette Boyle.
https://cs.idc.ac.il/~elette/


We implement 2-party 1-bit DPF with early termination and full domain evaluation. The reason we only implement 1-bit is that such construction is already sufficient for PIR-read and/or PIR-write.

AES-NI tools all from https://github.com/amaloz/libgarble.

The project is inspired by the discussion with Frank Wang in https://github.com/frankw2/libfss, their construction is more general, rather than specifically PIR-purpose one-bit implementation. We also use their idea of fixed key (and public) cipher (with AES-NI) to accelarate and simplify the one-way function. For details, please check this paper in NSDI'17.

Frank Wang, Catherine Yun, Shafi Goldwasser, Vinod Vaikuntanathan, and Matei Zaharia. "Splinter: Practical Private Queries on Public Data." NSDI 2017. https://www.usenix.org/system/files/conference/nsdi17/nsdi17-wang-frank.pdf

## How to install

Install cmake and libssl-dev. use "cmake ." to generate Makefile, and then make.

Note that our implementation strongly requires AES-NI. Please check whether the Flags in /proc/cpuinfo indicated "aes".

We consider the machine to be at least 64-bit.
