## Classic McEliece / Niederreiter Overview

This fork focuses on the McEliece scheme, the variant Niederreiter cryptosystem, the Fujisaki–Okamoto (FO) transform, the Classic McEliece KEM structure, and notes on randomness.

### Summary
- McEliece & Niederreiter base: OW‑CPA hard decoding problem on binary Goppa codes.
- Classic McEliece KEM: applies FO transform + implicit rejection ⇒ IND‑CCA2.
- Randomness analysis of $e$ is done as a lightweight statistical sanity checks.
- Randomness analysis of the hash function used for the Fujisaki-Okamoto transform pending. 
- Formal validation (e.g., NIST STS, Dieharder) and side‑channel analysis pending.

### 1. McEliece Cryptosystem
Consider some efficiently decodable family of $[n, k]$-codes $\mathcal{C}$ correcting $t$ errors. In the context of McEliece encryption, this family usually consists of so-called Goppa
codes. Let $\mathbb{F}_2$ be the binary field and $\mathbb{F}_{2^m}$ an extension field. A binary Goppa code $\mathcal{C}$ is defined by a Goppa polynomial $g(x) \in \mathbb{F}_{2^m}[x]$ of degree $r$ and a support set $L = (\alpha_1,\ldots,\alpha_n) \subseteq \mathbb{F}_{2^m}$ with $g(\alpha_i) \neq 0$. A generator matrix of $\mathcal{C}$ is denoted $G \in \mathbb{F}_2^{k\times n}$.

Key generation samples two secret random invertible matrices: a permutation matrix $P \in \mathbb{F}_2^{n\times n}$ and an invertible scrambling matrix $S \in \mathbb{F}_2^{k\times k}$. The public key is the disguised generator matrix
$$T = P \, G \, S$$
(note: some descriptions use $T = S G P$ depending on left/right action conventions; here columns are permuted on the left by $P$). The secret key contains $(G, S, P)$ plus any decoding information for the underlying Goppa code.

Encryption of a message $m \in \{0,1\}^k$:
1. Sample a random error vector $e \in \{0,1\}^n$ of fixed Hamming weight $t$ (uniform over all weight-$t$ vectors).
2. Compute the ciphertext (all operations over $\mathbb{F}_2$)
$$c := T \, m + e$$

Decryption:
1. Undo permutation: $c' := P^{-1} c = G S m + P^{-1} e$.
2. Use the error correction to remove the error part $e' = P^{-1} e$ from $c'$, and get $G S m$.
3. Get $m$ using $S^{-1} G^{-1}$: $m= S^{-1} G^{-1} (G S m)$.

Security: The scheme is one‑way under chosen‑plaintext attack (OW‑CPA): given a random ciphertext $c$ it is hard on average to recover $m$ (or $e$) without the secret key, assuming the hardness of decoding a random Goppa code. The scheme as stated is not IND‑CCA2; a transform (e.g., Fujisaki–Okamoto) is required for CCA security.

### 2. Niederreiter Cryptosystem (Variant of McEliece)
Niederreiter cryptosystem is the variant of McEliece, and it is OW-CPA if McEliece is OW-CPA (for the same code and parameters).
Let $\mathcal{C}$ be an efficiently decodable $[n,k]$-linear Goppa code over $\mathbb{F}_2$ that corrects up to $t$ errors, with parity‑check matrix $H \in \mathbb{F}_2^{(n-k) \times n}$. Let $d$ denote any auxiliary decoding information (e.g., structure of a Goppa code).

Key generation:
1. Sample an invertible scrambling matrix $S \in \mathrm{GL}_{n-k}(\mathbb{F}_2)$.
2. Sample a permutation matrix $P \in \mathbb{F}_2^{n \times n}$.
3. Form the public matrix
$$T := S H P$$
4. Public key: $\text{pk} := T$. Secret key: $\text{sk} := (P, H, S, d)$.

Message space:
$$\mathcal{M} = \{ e \in \{0,1\}^n : \text{wt}(e) = t \}$$
Each message is itself an error vector of fixed Hamming weight $t$ (non‑standard encoding, but convenient for security proofs / reductions).

Encryption of $e \in \mathcal{M}$:

$c := T e = S H P e$ 

(All operations over $\mathbb{F}_2$.)

Decryption of $c$:
1. Compute $c' := S^{-1} c = H P e$.
2. Since $P$ is a permutation, $\text{wt}(P e) = t$. Run the (syndrome) decoding algorithm for $H$ (using $d$ if needed) to recover $P e$ from $c'$.
3. Output $e = P^{-1} (P e)$.

Correctness follows because $c'$ is precisely the syndrome of $P e$ under $H$. Security: This scheme is one‑way under chosen‑plaintext attack (OW‑CPA) assuming the hardness of decoding a random weight‑$t$ error for the underlying code family.

### 3. Classic McEliece (KEM with ROM and QROM IND-CCA2 security using Fujisaki–Okamoto (FO) like transformation with implicit rejection)
Classic McEliece (NIST PQC selection for code‑based encryption) modernizes the original design with carefully chosen binary Goppa code parameters providing targeted security levels (NIST L1–L5) and adopts constant‑time, side‑channel aware implementations.

More precisely, Classic McEliece is specified and implemented as a KEM: it encapsulates a uniformly distributed shared secret rather than directly encrypting arbitrary plaintext. Operationally, the Niederreiter variant serves as the core OW‑CPA primitive; a Fujisaki–Okamoto (FO) like transform with implicit rejection is then applied to reach IND‑CCA2 security.

### 4. Security Notions: From OW‑CPA to IND‑CCA2
Base McEliece / Niederreiter provides only OW‑CPA (one‑wayness under chosen‑plaintext attacks). To obtain IND‑CCA2 (confidentiality under adaptive chosen‑ciphertext attacks), Classic McEliece applies the Fujisaki–Okamoto (FO) like transform with implicit rejection. Below is a high-level overview of the transform:
- Sample error vector e uniformly among weight‑t vectors (core randomness).
- Derive a candidate shared secret K = H1(e || pk) with a hash / XOF (domain separation ensures binding to the public key).
- Form ciphertext components deterministically from e (Niederreiter syndrome) plus a re-encryption consistency hash; include H2(e || pk) where specification requires.
- On decapsulation: attempt to decode, recompute what the ciphertext should be from the recovered e; if mismatch, set e' = H3(ciphertext || sk) (implicit rejection) ensuring no decryption oracle leakage, then derive K' = H1(e' || pk).
This transforms decoding failures or malicious modifications into pseudorandom outputs, preventing adaptive distinguishing attacks.

### 5. Randomness Sources & Simple Measurement
Key security hinges on high‑quality randomness for:
1. Error vector e (weight‑t selection must be uniform across all weight‑t subsets of positions).
2. Hash outputs (FO transform hashes H1, H2, etc.).

Practical lightweight checks (not a substitute for formal statistical analysis):
- Collect N (e.g., 10^4) sampled error vectors; verify each has exact weight t; compute frequency of each position being a 1 and ensure all frequencies lie within an acceptable deviation band (e.g., ±3σ of expected t/n).
- Perform pairwise collision count on e samples; observed collisions should align with birthday bound expectations (very low for chosen N).
- For hash outputs used to derive shared secrets, concatenate many outputs and test bit balance (ratio of ones to total bits ~ 0.5 within tolerance) and approximate min‑entropy per byte (no value dominating excessively).
- Use a chi‑square uniformity test across byte values for aggregated hash output (p-value in a non‑extreme interval, e.g., 0.01–0.99).

#### 5.1 Implemented Internal Instrumentation for `e` Sampling
To move beyond black‑box sanity checks, this fork adds optional compile‑time instrumentation to observe and summarize the distribution of positions selected in the Niederreiter / Classic McEliece error vector `e`.

Location (example parameter set instrumented):
`src/kem/classic_mceliece/pqclean_mceliece6960119_clean/encrypt.c`

Instrumentation is guarded by the macro `OQS_MEASURE_E_RANDOMNESS` so normal (constant‑time focused) builds are unaffected.

Added elements (inside `#ifdef OQS_MEASURE_E_RANDOMNESS`):
- Global counters:
	- `static uint64_t e_index_frequency[SYS_N];`  counts how often each coordinate 0..SYS_N-1 appears in sampled error vectors.
	- `static uint64_t e_sample_count;` number of successfully generated error vectors.
	- `static uint64_t e_restart_count;` number of rejected attempts (loops) due to duplicate indices when enforcing distinct positions.
- Hook points in `gen_e`:
	- After detecting a duplicate and restarting, `oqs_mceliece_record_e_restart()` increments `e_restart_count`.
	- After a valid set of indices is chosen (just before packing bits), `oqs_mceliece_record_e_indices(ind, SYS_T)` updates per‑index frequencies and increments `e_sample_count`.
- Public (internal) reporting function:
	- `void oqs_mceliece_dump_e_randomness_stats(void);`
		* Computes: expected frequency per index `expected = samples * SYS_T / SYS_N`.
		* Aggregates: min / max index frequency, number of zero‑hit indices, total restarts.
		* Computes a Pearson chi‑square statistic:

			$$
\chi^2 = \sum_{i=0}^{\mathrm{SYS\_N}-1} \frac{(f_i - \mathrm{expected})^2}{\mathrm{expected}}
$$
(df = SYS_N - 1) as a rough uniformity indicator over coordinate selection.
		* Emits a single summary line to `stderr` with these values.

Snippet of added usage points (conceptually):
```
gen_e(e) {
		...
		if (duplicate_indices) oqs_mceliece_record_e_restart();
		...
		oqs_mceliece_record_e_indices(ind, SYS_T);
}
```

Build & usage:
1. Configure with the macro enabled (example CMake invocation):
	 - `cmake -S . -B build -DOQS_ENABLE_KEM_CLASSIC_MCELIECE=ON -DBUILD_SHARED_LIBS=ON -DCMAKE_C_FLAGS="-DOQS_MEASURE_E_RANDOMNESS"`
2. Run a workload that performs many encapsulations / `encrypt` calls.
3. From any test or added harness (after operations), call:
	 - `oqs_mceliece_dump_e_randomness_stats();`
4. Inspect stderr output, e.g.:
	 `[e-rand] samples=1000, restarts=12, expected_per_index=3.45, min=0, max=7, zeros=15, chi^2=1043.27 (df=6960119)` (illustrative only).

Interpretation guidance:
- `restarts` gives an efficiency view of rejection sampling (should be modest relative to samples).
- `zeros` (indices never selected) should shrink as sample size grows; a persistently large fraction may indicate bias.
- `chi^2` compared to chi‑square distribution (optionally approximate via (chi^2 - df) / sqrt(2*df)) gives a standardized deviation score; very large outliers signal non‑uniformity.

Security / safety notes:
- Instrumentation introduces side channels (extra branches, memory writes, I/O) and must not be used in production or benchmarking constant‑time performance.
- Only one parameter set file was instrumented (6960119 clean variant) for demonstration; analogous edits can be propagated to other variants if needed.
- No header was added: functions are confined to the translation unit unless the user declares them elsewhere for manual invocation. This minimizes API surface changes.

Possible future enhancements:
- Add a generic macro layer to instrument all Classic McEliece parameter sets.
- Export a small header (guarded) to allow external test harnesses to trigger dumps without `extern` declarations.
- Include variance / standard deviation reporting or simple p‑value estimation.

---
Below are the original README.md of the liboqs repo
======================

[![Main Branch Tests](https://github.com/open-quantum-safe/liboqs/actions/workflows/commit-to-main.yml/badge.svg)](https://github.com/open-quantum-safe/liboqs/actions/workflows/commit-to-main.yml)
[![Weekly Tests](https://github.com/open-quantum-safe/liboqs/actions/workflows/weekly.yml/badge.svg)](https://github.com/open-quantum-safe/liboqs/actions/workflows/weekly.yml)
![Travis Build Status](https://img.shields.io/travis/com/open-quantum-safe/liboqs?logo=travis&label=Travis%20CI&labelColor=%23343B42&color=%232EBB4E)
[![Coverage Status](https://coveralls.io/repos/github/open-quantum-safe/liboqs/badge.svg?branch=main)](https://coveralls.io/github/open-quantum-safe/liboqs?branch=main)

liboqs is an open source C library for quantum-safe cryptographic algorithms.

- [liboqs](#liboqs)
	- [Overview](#overview)
	- [Status](#status)
		- [Supported Algorithms](#supported-algorithms)
			- [Key encapsulation mechanisms](#key-encapsulation-mechanisms)
			- [Signature schemes](#signature-schemes)
		- [Limitations and Security](#limitations-and-security)
			- [Platform limitations](#platform-limitations)
	- [Quickstart](#quickstart)
		- [Linux and Mac](#linux-and-mac)
		- [Windows](#windows)
		- [Cross compilation](#cross-compilation)
	- [Documentation](#documentation)
	- [Contributing](#contributing)
	- [License](#license)
	- [Acknowledgements](#acknowledgements)

## Overview

liboqs provides:

- a collection of open source implementations of quantum-safe key encapsulation mechanism (KEM) and digital signature algorithms; the full list can be found [below](#supported-algorithms)
- a common API for these algorithms
- a test harness and benchmarking routines

liboqs is part of the **Open Quantum Safe (OQS)** project, which aims to develop and integrate into applications quantum-safe cryptography to facilitate deployment and testing in real world contexts. In particular, OQS provides prototype integrations of liboqs into protocols like TLS, X.509, and S/MIME, through our [OpenSSL 3 Provider](https://github.com/open-quantum-safe/oqs-provider) and we provide a variety of other [post-quantum-enabled demos](https://github.com/open-quantum-safe/oqs-demos).

The OQS project is supported by the [Post-Quantum Cryptography Alliance](https://pqca.org/) as part of the [Linux Foundation](https://linuxfoundation.org/). More information about the Open Quantum Safe project can be found at [openquantumsafe.org](https://openquantumsafe.org/).

OQS is running a survey to better understand our community. We would like to hear from organizations and individuals about their interest in and use of the Open Quantum Safe project. Please take a few minutes to fill out the survey: https://linuxfoundation.surveymonkey.com/r/oqssurvey

## Status

### Supported Algorithms

Details on each supported algorithm can be found in the [docs/algorithms](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms) folder.

The list below indicates all algorithms currently supported by liboqs, including experimental algorithms and already excluding algorithm variants pruned during the NIST competition, such as Kyber-90s or Dilithium-AES.

The only algorithms in `liboqs` that implement NIST standards are the [`ML-KEM`](https://csrc.nist.gov/pubs/fips/203/final) (final standard) and [`ML-DSA`](https://csrc.nist.gov/pubs/fips/204/final) (final standard) variants with their respective different bit strengths. `liboqs` will retain these algorithm names selected by NIST throughout the finishing stages of the standardization process, so users can rely on their presence going forward. If NIST changes the implementation details of these algorithms, `liboqs` will adjust the implementation so that users are protected from such potential changes.

Falcon and SPHINCS+ have also been [selected for standardization](https://csrc.nist.gov/Projects/post-quantum-cryptography/selected-algorithms-2022), but the `liboqs` implementations of these algorithms are currently tracking Round 3 submissions and not NIST standards drafts.

All names other than `ML-KEM` and `ML-DSA` are subject to change. `liboqs` makes available a [selection mechanism for algorithms on the NIST standards track, continued NIST competition, or purely experimental nature by way of the configuration variable OQS_ALGS_ENABLED](CONFIGURE.md#oQS_ALGS_ENABLED). By default `liboqs` is built supporting all, incl. experimental, PQ algorithms listed below.

#### Key encapsulation mechanisms

<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START -->
- **BIKE**: BIKE-L1, BIKE-L3, BIKE-L5
- **Classic McEliece**: Classic-McEliece-348864†, Classic-McEliece-348864f†, Classic-McEliece-460896†, Classic-McEliece-460896f†, Classic-McEliece-6688128†, Classic-McEliece-6688128f†, Classic-McEliece-6960119†, Classic-McEliece-6960119f†, Classic-McEliece-8192128†, Classic-McEliece-8192128f†
- **FrodoKEM**: FrodoKEM-640-AES, FrodoKEM-640-SHAKE, FrodoKEM-976-AES, FrodoKEM-976-SHAKE, FrodoKEM-1344-AES, FrodoKEM-1344-SHAKE
- **HQC**: HQC-128, HQC-192, HQC-256
- **Kyber**: Kyber512, Kyber768, Kyber1024
- **ML-KEM**: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **NTRU-Prime**: sntrup761
<!--- OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END -->

#### Signature schemes

<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START -->
- **CROSS**: cross-rsdp-128-balanced, cross-rsdp-128-fast, cross-rsdp-128-small†, cross-rsdp-192-balanced, cross-rsdp-192-fast, cross-rsdp-192-small†, cross-rsdp-256-balanced†, cross-rsdp-256-fast, cross-rsdp-256-small†, cross-rsdpg-128-balanced, cross-rsdpg-128-fast, cross-rsdpg-128-small, cross-rsdpg-192-balanced, cross-rsdpg-192-fast, cross-rsdpg-192-small†, cross-rsdpg-256-balanced, cross-rsdpg-256-fast, cross-rsdpg-256-small†
- **CRYSTALS-Dilithium**: Dilithium2, Dilithium3, Dilithium5
- **Falcon**: Falcon-512, Falcon-1024, Falcon-padded-512, Falcon-padded-1024
- **MAYO**: MAYO-1, MAYO-2, MAYO-3, MAYO-5†
- **ML-DSA**: ML-DSA-44, ML-DSA-65, ML-DSA-87
- **SNOVA**: SNOVA\_24\_5\_4, SNOVA\_24\_5\_4\_SHAKE, SNOVA\_24\_5\_4\_esk, SNOVA\_24\_5\_4\_SHAKE\_esk, SNOVA\_37\_17\_2†, SNOVA\_25\_8\_3, SNOVA\_56\_25\_2†, SNOVA\_49\_11\_3†, SNOVA\_37\_8\_4†, SNOVA\_24\_5\_5†, SNOVA\_60\_10\_4†, SNOVA\_29\_6\_5†
- **SPHINCS+-SHA2**: SPHINCS+-SHA2-128f-simple, SPHINCS+-SHA2-128s-simple, SPHINCS+-SHA2-192f-simple, SPHINCS+-SHA2-192s-simple, SPHINCS+-SHA2-256f-simple, SPHINCS+-SHA2-256s-simple
- **SPHINCS+-SHAKE**: SPHINCS+-SHAKE-128f-simple, SPHINCS+-SHAKE-128s-simple, SPHINCS+-SHAKE-192f-simple, SPHINCS+-SHAKE-192s-simple, SPHINCS+-SHAKE-256f-simple, SPHINCS+-SHAKE-256s-simple
- **UOV**: OV-Is, OV-Ip, OV-III, OV-V, OV-Is-pkc, OV-Ip-pkc, OV-III-pkc, OV-V-pkc, OV-Is-pkc-skc, OV-Ip-pkc-skc, OV-III-pkc-skc, OV-V-pkc-skc
<!--- OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END -->
- **XMSS**: XMSS-SHA2_10_256, XMSS-SHA2_16_256, XMSS-SHA2_20_256, XMSS-SHAKE_10_256, XMSS-SHAKE_16_256, XMSS-SHAKE_20_256, XMSS-SHA2_10_512, XMSS-SHA2_16_512, XMSS-SHA2_20_512, XMSS-SHAKE_10_512, XMSS-SHAKE_16_512, XMSS-SHAKE_20_512, XMSS-SHA2_10_192, XMSS-SHA2_16_192, XMSS-SHA2_20_192, XMSS-SHAKE256_10_192, XMSS-SHAKE256_16_192, XMSS-SHAKE256_20_192, SHAKE256_10_256, SHAKE256_16_256, SHAKE256_20_256, XMSSMT-SHA2_20/2_256, XMSSMT-SHA2_20/4_256, XMSSMT-SHA2_40/2_256, XMSSMT-SHA2_40/4_256, XMSSMT-SHA2_40/8_256, XMSSMT-SHA2_60/3_256, XMSSMT-SHA2_60/6_256, XMSSMT-SHA2_60/12_256, XMSSMT-SHAKE_20/2_256, XMSSMT-SHAKE_20/4_256, XMSSMT-SHAKE_40/2_256, XMSSMT-SHAKE_40/4_256, XMSSMT-SHAKE_40/8_256, XMSSMT-SHAKE_60/3_256, XMSSMT-SHAKE_60/6_256, XMSSMT-SHAKE_60/12_256 
- **LMS**: LMS_SHA256_H5_W1, LMS_SHA256_H5_W2, LMS_SHA256_H5_W4, LMS_SHA256_H5_W8, LMS_SHA256_H10_W1, LMS_SHA256_H10_W2, LMS_SHA256_H10_W4, LMS_SHA256_H10_W8, LMS_SHA256_H15_W1, LMS_SHA256_H15_W2, LMS_SHA256_H15_W4, LMS_SHA256_H15_W8, LMS_SHA256_H20_W1, LMS_SHA256_H20_W2, LMS_SHA256_H20_W4, LMS_SHA256_H20_W8, LMS_SHA256_H25_W1, LMS_SHA256_H25_W2, LMS_SHA256_H25_W4, LMS_SHA256_H25_W8, LMS_SHA256_H5_W8_H5_W8, LMS_SHA256_H10_W4_H5_W8, LMS_SHA256_H10_W8_H5_W8, LMS_SHA256_H10_W2_H10_W2, LMS_SHA256_H10_W4_H10_W4, LMS_SHA256_H10_W8_H10_W8, LMS_SHA256_H15_W8_H5_W8, LMS_SHA256_H15_W8_H10_W8, LMS_SHA256_H15_W8_H15_W8, LMS_SHA256_H20_W8_H5_W8, LMS_SHA256_H20_W8_H10_W8, LMS_SHA256_H20_W8_H15_W8, LMS_SHA256_H20_W8_H20_W8

Note that for algorithms marked with a dagger (†), liboqs contains at least one implementation that uses a large amount of stack space; this may cause failures when run in threads or in constrained environments. For more information, consult the algorithm information sheets in the [docs/algorithms](https://github.com/open-quantum-safe/liboqs/tree/main/docs/algorithms) folder.

### Limitations and Security

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this library, caution is advised when deploying quantum-safe algorithms as most of the algorithms and software have not been subject to the same degree of scrutiny as for currently deployed algorithms. Particular attention should be paid to guidance provided by the standards community, especially from the NIST [Post-Quantum Cryptography Standardization](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization) project.  As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers. Moreover, note that the `sntrup761` is only included for interop testing.

liboqs does not intend to "pick winners": algorithm support is informed by the NIST PQC standardization project. We strongly recommend that applications and protocols rely on the outcomes of this effort when deploying post-quantum cryptography.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the NIST PQC standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

**WE DO NOT CURRENTLY RECOMMEND RELYING ON THIS LIBRARY IN A PRODUCTION ENVIRONMENT OR TO PROTECT ANY SENSITIVE DATA.** This library is meant to help with research and prototyping.  While we make a best-effort approach to avoid security bugs, this library has not received the level of auditing and analysis that would be necessary to rely on it for high security use.

Please see [SECURITY.md](SECURITY.md#security-policy) for details on how to report a vulnerability and the OQS vulnerability response process.

#### Platform limitations

In order to optimize support effort,
- not all algorithms are equally well supported on all platforms. In case of questions, it is first advised to review the [documentation files for each algorithm](docs/algorithms).
- not all compilers are equally well supported. For example, at least v7.1.0 of the GNU compiler is required.

#### Support limitations

This project is not commercially supported. All guidelines and goals for liboqs are reflections of current practices, executed by a community of academic, part-time, and/or voluntary contributors on a best-effort basis and may change at any time. Any entity seeking more reliable commitments is strongly encouraged to join the OQS community and thus enhance the code and support that the community can provide.


## Quickstart

### Linux and Mac

1. Install dependencies:

	On Ubuntu:

		 sudo apt install astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind

	On macOS, using a package manager of your choice (we've picked Homebrew):

		brew install cmake ninja openssl@3 wget doxygen graphviz astyle valgrind
		pip3 install pytest pytest-xdist pyyaml

	Using Nix:

		nix develop

	Note that, if you want liboqs to use OpenSSL for various symmetric crypto algorithms (AES, SHA-2, etc.) then you must have OpenSSL installed (version 3.x recommended; EOL version 1.1.1 also still possible).

2. Get the source:

		git clone -b main https://github.com/open-quantum-safe/liboqs.git
		cd liboqs

	and build:

		mkdir build && cd build
		cmake -GNinja ..
		ninja

Various `cmake` build options to customize the resultant artifacts are available and are [documented in CONFIGURE.md](CONFIGURE.md#options-for-configuring-liboqs-builds). All supported options are also listed in the `.CMake/alg-support.cmake` file, and can be viewed by running `cmake -LAH -N ..` in the `build` directory.

The following instructions assume we are in `build`.

3. By default the main build result is `lib/liboqs.a`, a static library. If you want to build a shared/dynamic library, append [`-DBUILD_SHARED_LIBS=ON`](CONFIGURE.md#bUILD_SHARED_LIBS) to the `cmake -GNinja ..` command above and the result will be `lib/liboqs.so|dylib|dll`. The public headers are located in the `include` directory. There are also a variety of programs built under the `tests` directory:

	- `test_kem`: Simple test harness for key encapsulation mechanisms
	- `test_sig`: Simple test harness for signature schemes
	- `test_sig_stfl`: Simple test harness for stateful signature schemes
	- `test_kem_mem`: Simple test harness for checking memory consumption of key encapsulation mechanisms
	- `test_sig_mem`: Simple test harness for checking memory consumption of signature schemes
	- `kat_kem`: Program that generates known answer test (KAT) values for key encapsulation mechanisms using the same procedure as the NIST submission requirements, for checking against submitted KAT values using `tests/test_kat.py`
	- `kat_sig`: Program that generates known answer test (KAT) values for signature schemes using the same procedure as the NIST submission requirements, for checking against submitted KAT values using `tests/test_kat.py`
	- `kat_sig_stfl`: Program for checking results against submitted KAT values using `tests/test_kat.py`
	- `speed_kem`: Benchmarking program for key encapsulation mechanisms; see `./speed_kem --help` for usage instructions
	- `speed_sig`: Benchmarking program for signature mechanisms; see `./speed_sig --help` for usage instructions
	- `speed_sig_stfl`: Benchmarking program for stateful signature mechanisms; see `./speed_sig_stfl --help` for usage instructions
	- `example_kem`: Minimal runnable example showing the usage of the KEM API
	- `example_sig`: Minimal runnable example showing the usage of the signature API
	- `example_sig_stfl`: Minimal runnable example showing the usage of the stateful signature API
	- `test_aes`, `test_sha3`: Simple test harnesses for crypto sub-components
	- `test_portability`: Simple test harnesses for checking cross-CPU code portability; requires presence of `qemu`; proper operation validated only on Ubuntu

	The complete test suite can be run using

		ninja run_tests

4. To generate HTML documentation of the API, run:

		ninja gen_docs

	Then open `docs/html/index.html` in your web browser.

4. `ninja install` can be run to install the built library and `include` files to a location of choice, which can be specified by passing the `-DCMAKE_INSTALL_PREFIX=<dir>` option to `cmake` at configure time. Alternatively, `ninja package` can be run to create an install package.

5. `ninja uninstall` can be run to remove all installation files.


### Windows

Binaries can be generated using Visual Studio 2019 with the [CMake Tools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.cmake-tools) extension installed. The same options as explained above for Linux/macOS can be used and build artifacts are generated in the specified `build` folders.

If you want to create Visual Studio build files, e.g., if not using `ninja`, be sure to _not_ pass the parameter `-GNinja` to the `cmake` command as exemplified above. You can then build all components using `msbuild`, e.g. as follows: `msbuild ALL_BUILD.vcxproj` and install all artifacts e.g. using this command `msbuild INSTALL.vcxproj`.


### Cross compilation

You can cross compile liboqs for various platforms. Detailed information is available [in the Wiki](https://github.com/open-quantum-safe/liboqs/wiki/Platform-specific-notes-for-building-liboqs#cross-compiling).

## Documentation

More detailed information on building, optional build parameters, example applications, coding conventions and more can be found in the [wiki](https://github.com/open-quantum-safe/liboqs/wiki).

## Contributing

Contributions that meet the acceptance criteria are gratefully welcomed. See our [Contributing Guide](https://github.com/open-quantum-safe/liboqs/wiki/Contributing-Guide) for more details.

## License

liboqs is licensed under the MIT License; see [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/main/LICENSE.txt) for details.

liboqs includes some third party libraries or modules that are licensed differently; the corresponding subfolder contains the license that applies in that case.  In particular:

- `.CMake/CMakeDependentOption.cmake`: BSD 3-Clause License
- `src/common/common.c`: includes portions which are Apache License v2.0
- `src/common/crypto/aes/aes_c.c`: public domain or any OSI-approved license
- `src/common/crypto/aes/aes*_ni.c`: public domain
- `src/common/crypto/sha2/sha2_c.c`: public domain
- `src/common/crypto/sha3/xkcp_low` : CC0 (public domain), except `brg_endian.h` and `KeccakP-1600-AVX2.s`
- `src/common/crypto/sha3/xkcp_low/.../brg_endian.h` : BSD 3-Clause License
- `src/common/crypto/sha3/xkcp_low/.../KeccakP-1600-AVX2.s` : BSD-like [CRYPTOGAMS license](http://www.openssl.org/~appro/cryptogams/)
- `src/common/rand/rand_nist.c`: See file
- `src/kem/bike/additional`: Apache License v2.0
- `src/kem/classic_mceliece/pqclean_*`: public domain
- `src/kem/kyber/pqcrystals-*`: public domain (CC0) or Apache License v2.0
- `src/kem/kyber/pqclean_*`: public domain (CC0), and public domain (CC0) or Apache License v2.0, and public domain (CC0) or MIT, and MIT
- `src/kem/kyber/libjade_*` public domain (CC0) or Apache License v2.
- `src/kem/ml_kem/mlkem-native_*`: Apache License v2.0
- `src/sig/dilithium/pqcrystals-*`: public domain (CC0) or Apache License v2.0
- `src/sig/dilithium/pqclean_*`: public domain (CC0), and public domain (CC0) or Apache License v2.0, and public domain (CC0) or MIT, and MIT
-  src/sig/falcon/pqclean_\*\_aarch64 : Apache License v2.0
- `src/sig/mayo/*`: Apache License v2.0
- `src/sig/ml_dsa/pqcrystals-*`: public domain (CC0) or Apache License v2.0
- `src/sig/sphincs/pqclean_*`: CC0 (public domain)

## Acknowledgements

The OQS project is supported by the [Post-Quantum Cryptography Alliance](https://pqca.org/) as part of the [Linux Foundation](https://linuxfoundation.org/).

The OQS project was founded by Douglas Stebila and Michele Mosca at the University of Waterloo.  [Contributors to liboqs](https://github.com/open-quantum-safe/liboqs/blob/main/CONTRIBUTORS) include individual contributors, academics and researchers, and various companies, including Amazon Web Services, Cisco Systems, evolutionQ, IBM Research, Microsoft Research, SandboxAQ, and softwareQ.

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services, the Canadian Centre for Cyber Security, Cisco, the Unitary Fund, the NGI Assure Fund, and VeriSign Inc.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.
