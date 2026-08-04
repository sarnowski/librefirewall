defmodule Ctrld.PKI.KeyPair do
  @moduledoc """
  Key generation, key encoding, and the one definition of the SPKI
  fingerprint.

  The fingerprint is the string an administrator compares against what an
  appliance printed on its console, and it is defined once here so there is
  only ever one rendering of it: SHA-256 over the DER-encoded
  SubjectPublicKeyInfo, as 64 lowercase hexadecimal characters with no
  separators. It is taken over the public key rather than the certificate on
  purpose — the appliance's self-signed onboarding certificate and the
  certificate this server issues carry the same key, so a fingerprint verified
  at first contact still names the appliance after issuance.
  """

  alias Ctrld.PKI.Profile

  @doc "A fresh private key on the profile's curve."
  @spec generate() :: :public_key.private_key()
  def generate, do: :public_key.generate_key({:namedCurve, Profile.curve_oid()})

  @doc "The uncompressed public point of a private key."
  @spec public_point(:public_key.private_key()) :: binary()
  def public_point({:ECPrivateKey, _version, _private, _params, point, _attributes}), do: point

  @doc """
  The DER SubjectPublicKeyInfo of a public point on the profile's curve.

  This is the exact structure `openssl pkey -pubin -outform DER` writes, which
  is what makes the fingerprint below reproducible with ordinary tooling.
  """
  @spec spki_der(binary()) :: binary()
  def spki_der(point) when is_binary(point) do
    parameters = :public_key.der_encode(:EcpkParameters, {:namedCurve, Profile.curve_oid()})

    :public_key.der_encode(
      :SubjectPublicKeyInfo,
      {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, Profile.ec_public_key_oid(), parameters},
       point}
    )
  end

  @doc "The SPKI fingerprint of a public point: 64 lowercase hexadecimal characters."
  @spec fingerprint(binary()) :: String.t()
  def fingerprint(point) when is_binary(point) do
    point
    |> spki_der()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  @doc "A private key as PEM, for sealing into the vault."
  @spec private_key_pem(:public_key.private_key()) :: String.t()
  def private_key_pem({:ECPrivateKey, _, _, _, _, _} = key) do
    :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, key)])
  end

  @doc """
  A private key read back out of the vault.

  Returns `:error` rather than raising on anything that is not one EC private
  key: the bytes have been through a database and a cipher, and a decode
  failure is a corrupted record to report, not a crash to take.
  """
  @spec private_key_from_pem(String.t()) :: {:ok, :public_key.private_key()} | :error
  def private_key_from_pem(pem) when is_binary(pem) do
    case :public_key.pem_decode(pem) do
      [{:ECPrivateKey, _der, :not_encrypted} = entry] ->
        case :public_key.pem_entry_decode(entry) do
          {:ECPrivateKey, _, _, _, _, _} = key -> {:ok, key}
          _other -> :error
        end

      _other ->
        :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end
end
