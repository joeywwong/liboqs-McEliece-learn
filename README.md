## Classic McEliece / Niederreiter Overview

This fork adds background on McEliece, Niederreiter, the Classic McEliece KEM, and experimental randomness measurements. The generator-matrix examples below explain the original cryptosystems; Classic McEliece uses a systematic parity-check matrix.

### Summary

- McEliece / Niederreiter one-wayness relies on the difficulty of recovering a random error of the prescribed weight for the generated binary Goppa codes.
- Classic McEliece uses a specific FO-like KEM construction with implicit rejection; its IND-CCA2 analysis is conditional on cryptographic assumptions and the ROM / QROM model.
- Measurements of `e` are statistical sanity checks, not security proofs or formal verification. Statistical hash-output testing and side-channel analysis are separate work.

### 1. McEliece Cryptosystem

Work over $\mathbb F_2$, with **row vectors** throughout these examples. Let $G\in\mathbb F_2^{k\times n}$ be a full-row-rank generator matrix for an efficiently decodable binary $[n,k]$ code correcting up to $t$ errors. A binary Goppa code is defined by a polynomial $g(x)\in\mathbb F_{2^a}[x]$ and distinct support elements $\alpha_i$ with $g(\alpha_i)\ne0$; the secret includes the information needed to decode it.

Key generation chooses an invertible scrambling matrix $S\in\mathbb F_2^{k\times k}$ and a permutation matrix $P\in\mathbb F_2^{n\times n}$. The public generator is

$$T=SGP\in\mathbb F_2^{k\times n}.$$

Right multiplication by $P$ permutes the $n$ coordinates (columns of $G$). To encrypt $m\in\mathbb F_2^{1\times k}$, sample $e\in\mathbb F_2^{1\times n}$ uniformly among weight-$t$ vectors and compute

$$c=mT+e\in\mathbb F_2^{1\times n}.$$

Decryption:

1. Undo the permutation: $c'=cP^{-1}=mSG+eP^{-1}$. Permutation preserves the error weight.
2. Decode $c'$ using the secret code structure to recover the codeword $w=mSG\in\mathbb F_2^{1\times n}$.
3. Recover its information vector $u=mS\in\mathbb F_2^{1\times k}$ by solving $uG=w$. For example, choose $k$ independent columns indexed by $J$; then $G_J\in\mathbb F_2^{k\times k}$ is invertible and $u=w_JG_J^{-1}$. If $G$ is systematic, read the corresponding information coordinates directly.
4. Compute $m=uS^{-1}$.

The rectangular matrix $G$ has no two-sided inverse. These equations use only inverses of square invertible matrices. One-wayness for random messages and errors is a hardness assumption for this key distribution, not a consequence of statistical tests or of worst-case decoding hardness alone. This base construction does not provide IND-CCA2 security.

### 2. Niederreiter Cryptosystem (Variant of McEliece)

Let $H\in\mathbb F_2^{(n-k)\times n}$ be a full-row-rank parity-check matrix for the secret code. Choose invertible $S_H\in\mathbb F_2^{(n-k)\times(n-k)}$ and permutation $P_H\in\mathbb F_2^{n\times n}$, and publish $H_{\rm pub}=S_HHP_H$.

The message is a row vector $e\in\mathbb F_2^{1\times n}$ of weight $t$. Its ciphertext is the syndrome

$$c=eH_{\rm pub}^{\mathsf T}=eP_H^{\mathsf T}H^{\mathsf T}S_H^{\mathsf T}\in\mathbb F_2^{1\times(n-k)}.$$

To decrypt, compute $c'=c(S_H^{\mathsf T})^{-1}=eP_H^{\mathsf T}H^{\mathsf T}$. Secret syndrome decoding recovers $v=eP_H^{\mathsf T}$ of weight $t$; then $e=v(P_H^{\mathsf T})^{-1}$. For the same code and parameters, this decoding-based one-wayness problem corresponds to that of McEliece. It does not by itself give chosen-ciphertext security.

### 3. Classic McEliece KEM and Its FO-like Construction

The implementation here follows the ordinary, non-`pc` construction in the [Classic McEliece specification (23 October 2022)](https://classic.mceliece.org/mceliece-spec-20221023.pdf), and the official Sage [encapsulation](https://classic.mceliece.org/mceliece-sage-20221023/encap.sage.html) and [decapsulation](https://classic.mceliece.org/mceliece-sage-20221023/decap.sage.html) definitions. Its public key stores the nonidentity block $A$ of a systematic parity-check matrix $H_{\rm pub}=(I_{at}\mid A)$, with $k=n-at$. This $A$ is called $T$ in the specification; it is different from the generator $T$ in Section 1 above.

For the instrumented clean 6960119 implementation, see `operations.c`, `encrypt.c`, `decrypt.c`, and `crypto_hash.h` in `src/kem/classic_mceliece/pqclean_mceliece6960119_clean/`:

- **Encapsulation:** `gen_e` samples a weight-$t$ vector; `syndrome` computes $c=eH_{\rm pub}^{\mathsf T}$. Derive the 32-byte shared secret $K=\operatorname{SHAKE256}_{32}(1\parallel e\parallel c)$. Here `0` and `1` are single domain-separation **bytes**, and vectors and ciphertexts use the specified byte encodings. For 6960119, $a=13$, $n=6960$, $t=119$: the syndrome has $at=1547$ bits, encoded in 194 bytes with five zero padding bits.
- **Decapsulation:** `decrypt` finds a candidate $\hat e$ and checks both its weight $t$ and its syndrome against the received ciphertext (via the secret Goppa-code representation). On success derive $K=\operatorname{SHAKE256}_{32}(1\parallel\hat e\parallel c)$. On decoding / validation failure derive $K=\operatorname{SHAKE256}_{32}(0\parallel s\parallel c)$, where $s$ is a secret $n$-bit fallback string stored during key generation, not a new error sample or a hash of the whole secret key. `operations.c` selects the preimage with masks. This is **implicit rejection**: for properly encoded ciphertexts, decoding failure returns a derived key without a failure status. Legitimate ciphertexts decode correctly.
- **Encoding errors are separate:** 6960119 rejects nonzero ciphertext padding with return value `-1` and an all-`0xFF` output key. Nonzero public-key padding makes encapsulation return `-1` and zero its outputs. Thus implicit rejection of a decoding failure does not mean every malformed byte string is accepted.

The ordinary ciphertext contains only the syndrome, with no separate confirmation hash. The [plaintext-confirmation (`pc`) variant](https://classic.mceliece.org/mceliece-pc-20221023.pdf) instead sends $c=(c_0,c_1)$ with $c_0=eH_{\rm pub}^{\mathsf T}$ and $c_1=H(2\parallel e)$, and additionally checks $c_1$ during decapsulation. That variant is not implemented by the parameter sets listed here; the suffix `f` denotes the fast key-generation variant, not plaintext confirmation.

### 4. Security Claims and Parameter Categories

“FO-like” describes the relationship to transformation techniques; a generic FO recipe is not a specification of this KEM. Here the Niederreiter primitive is deterministic once its input $e$ is fixed, decoding validates that input, and domain-separated hashes bind the shared secret to $e$ (or secret $s$) and the ciphertext. There is no $H_1(e\parallel\mathrm{pk})$ key derivation or invented $H_3(c\parallel\mathrm{sk})$ fallback.

The [security guide](https://classic.mceliece.org/mceliece-security-20221023.pdf), Sections 5.3–5.5, relates IND-CCA2 security in the random-oracle model (ROM) and quantum random-oracle model (QROM) to the relevant one-wayness assumptions, correctness, and the specified randomness generation. These are conditional reductions; modeling SHAKE256 as an oracle is an assumption, not a proof that the concrete hash or this fork's implementation is secure. Neither generic decoding hardness nor observed randomness alone establishes these claims.

The implemented parameter sets target the following **NIST security categories**, as claimed in the submission and recorded in `docs/algorithms/kem/classic_mceliece.yml` (the `f` variants have the same targets):

| Parameter sets (with or without `f`) | Target category | Reference comparison |
| --- | --- | --- |
| 348864 | 1 | AES-128 key search |
| 460896 | 3 | AES-192 key search |
| 6688128, 6960119, 8192128 | 5 | AES-256 key search |

These are attack-cost targets, not categories established by these experiments or a claim of NIST standardization. Statistical randomness tests, CSPRNG security (including adequate seeding and unpredictability), uniform fixed-weight sampling, IND-CCA2 security, side-channel resistance, and formal verification are distinct properties requiring different evidence. NIST STS, Dieharder, chi-square tests, bit balance, and empirical byte frequencies cannot prove any of these cryptographic security properties or certify min-entropy. See also [NIST SP 800-22 Rev. 1a](https://csrc.nist.gov/pubs/sp/800/22/r1/upd1/final).

### 5. Randomness Sources & Simple Measurement

Key generation and encapsulation require a cryptographically secure random source. `randombytes` maps to `OQS_randombytes` here. Under ideal independent uniform input bits, `gen_e`'s range rejection and rejection of duplicate indices produce a uniform weight-$t$ subset: every ordered sequence of distinct accepted indices is equally likely, and every subset has $t!$ orderings. A real CSPRNG supplies computational pseudorandomness; equal coordinate frequencies alone do not show uniformity over all $\binom nt$ subsets or independence between samples.

#### 5.1 Implemented Internal Instrumentation for `e` Sampling

Only `src/kem/classic_mceliece/pqclean_mceliece6960119_clean/encrypt.c` is instrumented, behind `OQS_MEASURE_E_RANDOMNESS`. The counters record accepted samples, coordinate frequencies, and restarts caused by duplicate indices. `restarts` excludes attempts with too few in-range indices, so it is not a count of all rejected attempts. Duplicate rejections need not be rare relative to accepted samples.

For $N>0$ independent uniform weight-$t$ vectors, let $f_i$ be the count for coordinate $i$, $p=t/n$, and $E=Np$. Then

$$\sum_i f_i=Nt,\qquad f_i\sim\operatorname{Binomial}(N,p),\qquad\operatorname{Var}(f_i)=Np(1-p).$$

Within each vector coordinates are negatively dependent; for $i\ne j$,

$$\operatorname{Cov}(f_i,f_j)=-\frac{Np(1-p)}{n-1}.$$

The reported Pearson-style statistic is

$$X_{\rm raw}^2=\sum_{i=0}^{n-1}\frac{(f_i-E)^2}{E},\qquad\mathbb E[X_{\rm raw}^2]=\frac{nNp(1-p)}{Np}=n-t.$$

Thus it is not the ordinary multinomial chi-square statistic. On the $(n-1)$-dimensional subspace $\sum_i(f_i-E)=0$, the covariance of $(f-E)/\sqrt E$ has eigenvalue $(n-t)/(n-1)$. The multivariate central limit theorem therefore gives, for fixed $n$ and $0<t<n$ as $N\to\infty$,

$$X_{\rm adjusted}^2=\frac{n-1}{n-t}X_{\rm raw}^2\ \xrightarrow{d}\ \chi^2_{n-1}.$$

The raw expectation is exact under the null; the adjusted chi-square law is only asymptotic. Sparse counts, large $n$ relative to $N$, dependent samples, and repeated testing can undermine calibration. The dump reports `chi2_raw`, `expected_chi2_raw`, `chi2_adjusted`, and `asymptotic_df`; it does not compute a p-value or a security verdict.

For **1,000 samples** at $n=6960$, $t=119$:

- Total selections are exactly 119,000; $E=119000/6960\approx17.10$ per coordinate.
- $\mathbb E[X_{\rm raw}^2]=6841$; $\mathbb E[X_{\rm adjusted}^2]=6959$ and the asymptotic degrees of freedom are 6959.
- A maximum count of 7 is impossible: some count must be at least $\lceil119000/6960\rceil=18$. No measured min, max, zero count, restart count, or statistic is asserted here.

Use a prespecified **global** test of coordinate balance, calibrated by the adjusted approximation only when justified, or by Monte Carlo: independently simulate many datasets of $N$ uniform weight-$t$ subsets, compute the same statistic, and compare the observation with that null distribution (e.g., upper-tail p-value $(1+\#\{X_b\ge X_{\rm obs}\})/(B+1)$ for $B$ simulations). Simulation must preserve fixed weight and use a trusted independent null sampler; it cannot repair dependence in the observed samples. Even this global frequency test cannot detect every nonuniform subset distribution or prove a CSPRNG secure.

An individual coordinate has standard deviation $\sqrt{Np(1-p)}$ for counts, or $\sqrt{p(1-p)/N}$ for frequencies. Requiring **every** coordinate to be within an individual $\pm3\sigma$ interval ignores 6960 comparisons (a normal approximation would predict about $6960\times0.0027\approx19$ exceedances on average, without assuming coordinate independence). Counts here are discrete and skewed, so that normal estimate is only illustrative. For coordinate-level follow-up, use exact binomial tails with a multiple-comparison correction such as Bonferroni, or calibrate the maximum deviation globally by the same fixed-weight Monte Carlo model. Prespecify significance levels and account for multiple workloads / tests.

Build & usage:

1. Configure with `-DCMAKE_C_FLAGS="-DOQS_MEASURE_E_RANDOMNESS"` and the desired Classic McEliece algorithm enabled.
2. Run a workload that actually calls the 6960119 **clean** implementation; other implementations do not update these counters.
3. After the workload, manually declare and call `void oqs_mceliece_dump_e_randomness_stats(void);` in an internal test. It prints sample counts, duplicate restarts, expected coordinate count, min / max, zeros, and both statistics to `stderr`. The function has external linkage but no public header or supported KEM API.

Instrumentation adds secret-dependent memory accesses and I/O. Use it only for controlled experiments, never production or constant-time / side-channel benchmarking. Normal builds exclude all instrumentation. Checks of exact weight, coordinate counts, or hash-output balance remain diagnostics; STS / Dieharder tests designed for unbiased bit streams should not be applied directly to the sparse, fixed-weight `e` vectors with an independent-fair-bit null model.

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
