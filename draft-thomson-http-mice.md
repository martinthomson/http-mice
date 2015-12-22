---
title: Merkle Integrity Content Encoding
abbrev: MICE
docname: draft-thomson-http-mice-latest
date: 2015
category: std

ipr: trust200902
area: General
workgroup:
keyword: Internet-Draft

stand_alone: yes
pi: [toc, tocindent, sortrefs, symrefs, strict, compact, comments, inline, docmapping]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com

normative:
  RFC2119:
  RFC4648:
  RFC5226:
  RFC7230:
  RFC7231:
  RFC7233:
  FIPS180-4:
    title: NIST FIPS 180-4, Secure Hash Standard
    author:
      name: NIST
      ins: National Institute of Standards and Technology, U.S. Department of Commerce
    date: 2012-03
    target: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
  MERKLE:
    title: "A Digital Signature Based on a Conventional Encryption Function"
    author:
      - ins: R. Merkle
    date: 1987
    seriesinfo: International Crytology Conference - CRYPTO
  FIPS186:
    title: "Digital Signature Standard (DSS)"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: July 2013
    seriesinfo: NIST PUB 186-4
  X9.62:
     title: "Public Key Cryptography For The Financial Services Industry: The Elliptic Curve Digital Signature Algorithm (ECDSA)"
     author:
       - org: ANSI
     date: 1998
     seriesinfo: ANSI X9.62

informative:
  RFC2818:
  RFC5246:
  RFC6962:
  SRI:
    title: "Subresource Integrity"
    author:
      - ins: D. Akhawe
      - ins: F. Braun
      - ins: F. Marier
      - ins: J. Weinberger

--- abstract

This memo introduces a content-coding for HTTP that provides integrity for
content that can be evaluated progressively.  This provides additional integrity
protection for the body of an HTTP message without losing the ability to process
the contents in a stream.


--- middle

# Introduction

Integrity protection for HTTP content is often necessary.  HTTPS [RFC2818] is
the most common form of integrity protection deployed, but that requires a
direct TLS [RFC5246] connection to a host.  However, additional integrity
protection is often desirable.  This might be for additional protection against
failures (e.g., [SRI]) or because content needs to traverse multiple
HTTPS-protected exchanges.

This document describes a "mi-sha256" content-encoding (see {{encoding}}) that
embeds a progressive, hash-based integrity check based on Merkle Hash Trees
[MERKLE].  This integrity scheme optionally supports including a digital
signature over the integrity value.

The means of conveying the root proof used by this content encoding will depend
on the requirements for deployment.  This document defines an MI header field
(see {{header}}) that can carry an integrity proof or signatures over the proof.


## Notational Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be
interpreted as described in [RFC2119].


# The "mi-sha256" HTTP Content Encoding {#encoding}

A Merkle Hash Tree [MERKLE] is a structured integrity mechanism that collates
multiple integrity checks into a tree.  The leaf nodes of the tree contain data
(or hashes of data) and non-leaf nodes contain hashes of the nodes below them.

A balanced Merkle Hash Tree is used to efficiently prove membership in large
sets (such as in [RFC6962]).  However, in this case, a right-skewed tree is used
to provide a progressive integrity proof.  This integrity proof is used to
establish that a given record is part of a message.

The hash function used for "mi-sha256" content encoding is SHA-256 [FIPS180-4].  The
integrity proof for all records other than the last is the hash of the
concatenation of the record, the integrity proof of all subsequent records, and
a single octet with a value of 0x1:

~~~
   proof(r[i]) = r[i] || proof(r[i+1]) || 0x1
~~~

The integrity proof for the final record is the hash of the record with a single
octet with a value 0x0 appended:

~~~
   proof(r[last]) = r[last] || 0x0
~~~

{{ex-proofs}} shows the structure of the integrity proofs for a message that is
split into 4 blocks: A, B, C, D).  As shown, the integrity proof for the entire
message (that is, `proof(A)`) is derived from the content of the first block
(A), plus the value of the proof for the second and subsequent blocks.

~~~

    proof(A)
      /\
     /  \
    /    \
   A    proof(B)
         /\
        /  \
       /    \
      B    proof_C
             /\
            /  \
           /    \
          C    proof_D
                 |
                 |
                 D
~~~
{: #ex-proofs title="Proof structure for a message with 4 blocks"}

The final encoded message is formed from the first record, followed by an
arbitrary number of tuples of the integrity proof of the next record and then
the record itself.  Thus, in {{ex-proofs}}, the body is:

~~~
   A || proof(B) || B || proof(C) || C || proof(D) || D
~~~


## Record Splitting and Message Structure {#records}

In order to produce the final content encoding the content of the message is
split into equal-sized records.  The final record can contain less than the
defined record size.

The default record size for the "mi-sha256" content encoding is 4096 octets.
This refers to the length of each data block.  The MI header field MAY contain
an "rs" parameter that describes a different record size.

The final encoded stream comprises of a record ("rs" octets), followed by the
proof for the following record (32 octets).  This allows a receiver to validate
and act upon each record after receiving the proof that follows it.  The final
record is not followed by a proof.

Note:

: This content encoding increases the size of a message by 32 octets times the
  length of the message divided by the record size, rounded up, less one.  That
  is, 32 * (ceil(length / rs) - 1).

Constructing a message with the "mi-sha256" content encoding requires processing
of the records in reverse order, inserting the proof derived from each record
before that record.

This structure permits the use of range requests [RFC7233]. However, to validate
a given record, a contiguous sequence of records back to the start of the
message is needed.


## Validating Integrity Proofs

A receiver of a message with the "mi-sha256" content-encoding applied first
attempts to acquire the integrity proof for the first record.  If the MI header
field is present, a value might be included there.

Then, the message is read into records of size "rs" (based on the value in the
MI header field) plus 32 octets.  For each record:

1. Hash the record using SHA-256 with a single octet appended.  All records
   other than the last have an octet with value 0x1 appended, and the last
   record (which will be between 1 and "rs" octets in length) has an octet with
   value 0x0 appended.

2. For the first record:

   1. If a signature is known for the integrity proof for the first record and
      the receiver is configured to validate a signature for this message, then
      the signature is validated with the output of the hash as the signed
      message.  If this check passes, then the signature applies to the entire
      message if subsequent checks succeed.

   2. If the integrity proof for the first record is known, the integrity check
      passes if the output of SHA-256 is identical to the known value.

   3. If an integrity proof for the first record is not available, treat the
      message as not having integrity protection.

3. For all other records, check if the output of SHA-256 is equal to the
   expected value, then the integrity check passes.  The expected value is the
   last 32 octets of the previous record.

If an integrity check fails, the message SHOULD be discarded and the exchange
treated as an error unless explicitly configured otherwise.  For clients, treat
this as equivalent to a server error; servers SHOULD generate a 400 status code.
However, if the integrity proof for the first record is not known, this check
SHOULD NOT fail unless explicitly configured.


# The MI HTTP Header Field  {#header}

The MI HTTP header field describes the encrypted content encoding(s) that have
been applied to a payload body, and therefore how those content encoding(s) can
be removed.

The MI header field uses the extended ABNF syntax defined in Section 1.2 of
[RFC7230] and the `parameter` rule from [RFC7231]:

~~~
  MI = #mi_params
  encryption_params = [ parameter *( ";" parameter ) ]
~~~

If the payload is encoded more than once (as reflected by having multiple
content-codings that use the message integrity header field), each application
of the content encoding is reflected in the MI header field in the order in
which they were applied.

The MI header MAY be omitted if the sender intends for the receiver to acquire
the integrity proof for the first record by other means.


## MI Header Field Parameters

The following parameters are used in determining the content encryption key that
is used for encryption:

p:

: The "p" parameter carries an integrity proof for the first record of the
  message.  This provides integrity for the entire message body.  This value is
  encoded using base64 with the Base 64 Encoding with URL and Filename Safe
  Alphabet (Section 5 of [RFC4648]) with no padding.

p256ecdsa:

: The "p256ecdsa" parameter carries an ECDSA signature over the integrity proof
  for the first record of the message using P-256 [FIPS186] encoded as defined
  in [X9.62].  If present, the "p" parameter MAY be ignored and omitted.  This
  document doesn't describe how a receiver might determine that a particular key
  is accepted.

  Multiple values of this parameter might be provided.  If the "keyid" parameter
  is used to identify a key for each of these, the first "keyid" parameter to
  precede the "p256ecdsa" parameter is used.

keyid:

: The "keyid" parameter optionally identifies the key that was used to generate
  a signature.

rs:

: The "rs" parameter contains a positive decimal integer that describes the
  record size in octets.  This value MUST be greater than 0.  If the "rs"
  parameter is absent, the record size defaults to 4096 octets.


# Examples

TODO: write a little bit of code...


# Security Considerations

The integrity of an entire message body depends on the means by which the
integrity proof for the first record is protected.  If this value comes from the
same place as the message, then this provides only limited protection against
transport-level errors (something that TLS provides adequate protection
against).

Separate protection for header fields might be provided by other means if the
first record retrieved is the first record in the message, but range requests do
not allow for this option.

## Algorithm Agility

A new content encoding type is needed in order to define the use of a hash
function other than SHA-256.

A new parameter name for the MI header field is needed to support new digital
signature algorithms.


# IANA Considerations

## The "mi-sha256" HTTP Content Encoding

This memo registers the "mi-sha256" HTTP content-coding in the HTTP Content Codings
Registry, as detailed in {{encoding}}.

* Name: mi-sha256
* Description: A Merkle Hash Tree based content encoding that provides
               progressive integrity.
* Reference: this specification


## MI Header Field {#iana-header}

This memo registers the "MI" HTTP header field in the Permanent Message
Header Registry, as detailed in {{header}}.

* Field name: MI
* Protocol: HTTP
* Status: Standard
* Reference: this specification
* Notes:


## The HTTP MI Parameter Registry {#mi-registry}

This memo establishes a registry for parameters used by the "MI" header field
under the "Hypertext Transfer Protocol (HTTP) Parameters" grouping.  The
"Hypertext Transfer Protocol (HTTP) MI Parameters" registry operates under an
"Specification Required" policy [RFC5226].

Entries in this registry are expected to include the following information:

* Parameter Name: The name of the parameter.
* Purpose: A brief description of the purpose of the parameter.
* Reference: A reference to a specification that defines the semantics of the parameter.

The initial contents of this registry are:

### p parameter

* Parameter Name: p
* Purpose: The value of the integrity proof for the first record.
* Reference: this document

### keyid parameter

* Parameter Name: keyid
* Purpose: An identifier for the key that is used for signature over the integrity proof for the first record.
* Reference: this document

### p256ecdsa parameter

* Parameter Name: p256ecdsa
* Purpose: An ECDSA signature using P-256 over the integrity proof for the first record.
* Reference: this document

### rs parameter

* Parameter Name: rs
* Purpose: The size of the records used for progressive integrity protection.
* Reference: this document


--- back

# Acknowledgements

David Benjamin and Erik Nygren both separately suggested that something like
this might be valuable.


# FAQ

1. Why not include the first proof in the encoding?

   The requirements for the integrity proof for the first record require a great
   deal more flexibility than this allows for.  Transferring the proof
   separately is sometimes necessary.  Separating the value out allows for that
   to happen more easily.

2. Why do messages have to be processed in reverse to construct them?

   The final integrity value, no matter how it is derived, has to depend on
   every bit of the message.  That means that there are three choices: both
   sender and receiver have to process the whole message, the sender has to work
   backwards, or the receiver has to work backwards.  The current form is the
   best option of the three.  The expectation is that this will be useful for
   content that is generated once and sent multiple times, since the onerous
   backwards processing requirement can be amortized.
