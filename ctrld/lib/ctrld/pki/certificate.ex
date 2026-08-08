defmodule Ctrld.PKI.Certificate do
  @moduledoc """
  Building and signing the four certificates the management plane uses.

  Everything in an issued certificate comes from `Ctrld.PKI.Profile` and from
  what the caller knows — the subject name, the public key, and the instant of
  issuance. Nothing comes from a certificate signing request: a request is a
  proof of key possession and a name, never a way of reaching into the
  contents of what is issued, so this module takes a public key and a name and
  never a requested extension.

  Issuance can be refused, and there is one reason it is: the DER came out
  longer than the profile bounds a certificate at. That is checked here, on the
  issuing side, rather than left for an appliance to discover when it is handed
  something it has nowhere to put — the appliance's state record reserves the
  profile's bound and no more, so a certificate past it is one that would be
  accepted and then fail to persist, on a node with no way to say why. Here the
  only variable-length input is the subject name, and the answer is to shorten
  it.
  """

  require Record

  Record.defrecordp(
    :tbs,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  alias Ctrld.PKI.{KeyPair, Profile}

  @typedoc "What a certificate is issued as, and the extensions that follow from it."
  @type kind :: :certificate_authority | :device | {:channel_endpoint, :inet.ip4_address()}

  @typedoc "An issued certificate: its DER, and the facts a row records about it."
  @type issued :: %{
          der: binary(),
          serial: pos_integer(),
          not_before: DateTime.t(),
          not_after: DateTime.t(),
          subject_common_name: String.t(),
          spki_fingerprint: String.t()
        }

  @typedoc "Why nothing was issued."
  @type reason :: {:certificate_too_long, String.t(), pos_integer(), pos_integer()}

  @doc """
  Create a self-signed certificate authority.

  Returns the issued certificate and the key it was created with; the caller
  seals that key before it goes anywhere. A refusal leaves neither behind.
  """
  @spec create_authority(String.t(), DateTime.t()) ::
          {:ok, {issued(), :public_key.private_key()}} | {:error, reason()}
  def create_authority(name, now) when is_binary(name) do
    key = KeyPair.generate()
    point = KeyPair.public_point(key)

    with {:ok, issued} <- issue(:certificate_authority, name, point, name, key, now) do
      {:ok, {issued, key}}
    end
  end

  @doc """
  Issue an end-entity certificate under an authority.

  `kind` decides the extensions, and with them what the certificate may be
  used for; the profile is the only source of that.
  """
  @spec issue_under(
          kind(),
          String.t(),
          binary(),
          String.t(),
          :public_key.private_key(),
          DateTime.t()
        ) ::
          {:ok, issued()} | {:error, reason()}
  def issue_under(kind, subject, subject_point, issuer, issuer_key, now)
      when kind != :certificate_authority do
    issue(kind, subject, subject_point, issuer, issuer_key, now)
  end

  @doc "A refusal in the words the administrator who asked for the certificate needs."
  @spec describe(reason()) :: String.t()
  def describe({:certificate_too_long, subject, size, bound}) do
    "a certificate for #{inspect(subject)} encodes to #{size} bytes and the profile bounds one " <>
      "at #{bound}; shorten the subject name"
  end

  defp issue(kind, subject, subject_point, issuer, issuer_key, now) do
    serial = serial()
    not_before = DateTime.truncate(now, :second)
    not_after = shift_years(not_before, Profile.validity_years())

    certificate =
      tbs(
        version: :v3,
        serialNumber: serial,
        signature: {:SignatureAlgorithm, Profile.signature_oid(), :asn1_NOVALUE},
        issuer: rdn(issuer),
        validity: {:Validity, time(not_before), time(not_after)},
        subject: rdn(subject),
        subjectPublicKeyInfo:
          {:OTPSubjectPublicKeyInfo,
           {:PublicKeyAlgorithm, Profile.ec_public_key_oid(), {:namedCurve, Profile.curve_oid()}},
           {:ECPoint, subject_point}},
        extensions: Profile.extensions(kind)
      )

    der = :public_key.pkix_sign(certificate, issuer_key)
    bound = Profile.max_certificate_der_bytes()

    if byte_size(der) > bound do
      {:error, {:certificate_too_long, subject, byte_size(der), bound}}
    else
      {:ok,
       %{
         der: der,
         serial: serial,
         not_before: not_before,
         not_after: not_after,
         subject_common_name: subject,
         spki_fingerprint: KeyPair.fingerprint(subject_point)
       }}
    end
  end

  @doc "A certificate as PEM, one encapsulated structure and nothing around it."
  @spec pem(binary()) :: String.t()
  def pem(der) when is_binary(der) do
    :public_key.pem_encode([{:Certificate, der, :not_encrypted}])
  end

  @doc """
  A random positive serial occupying the profile's full width.

  The top bit of the leading byte is set, which is what keeps the value from
  ever being zero and from ever being narrower than the width the profile
  states.
  """
  @spec serial() :: pos_integer()
  def serial do
    <<leading, rest::binary>> = :crypto.strong_rand_bytes(div(Profile.serial_bits(), 8))
    :binary.decode_unsigned(<<Bitwise.bor(leading, 0x80), rest::binary>>)
  end

  defp rdn(common_name) do
    {:rdnSequence,
     [[{:AttributeTypeAndValue, Profile.common_name_oid(), {:utf8String, common_name}}]]}
  end

  defp shift_years(%DateTime{} = at, years), do: DateTime.shift(at, year: years)

  # RFC 5280: UTCTime through 2049, GeneralizedTime from 2050.
  defp time(%DateTime{year: year} = at) when year < 2050 do
    {:utcTime, format(at, 2) |> String.to_charlist()}
  end

  defp time(%DateTime{} = at), do: {:generalTime, format(at, 4) |> String.to_charlist()}

  defp format(%DateTime{} = at, year_digits) do
    year = at.year |> Integer.to_string() |> String.slice(-year_digits, year_digits)

    year <>
      pad(at.month) <> pad(at.day) <> pad(at.hour) <> pad(at.minute) <> pad(at.second) <> "Z"
  end

  defp pad(value), do: value |> Integer.to_string() |> String.pad_leading(2, "0")
end
