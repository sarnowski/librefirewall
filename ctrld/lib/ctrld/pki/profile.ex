defmodule Ctrld.PKI.Profile do
  @moduledoc """
  The one place every certificate parameter is written down.

  Issuance, request validation, and the tests all read this module, so there
  is a single answer to "what algorithm, what lifetime, what key usage" and no
  second copy of it to drift. Every value here is a decision taken with the
  appliance, which validates against the same set from its own side.

  The algorithm is a field and never an assumption: `key_algorithm/0` and
  `signature_algorithm/0` are what a consumer reads off an artifact and what a
  record stores, so moving the fleet to another signature algorithm later is a
  re-issuance against this module with the rows below changed, not a redesign.
  """

  @curve_oid {1, 2, 840, 10045, 3, 1, 7}
  @ec_public_key_oid {1, 2, 840, 10045, 2, 1}
  @ecdsa_with_sha256_oid {1, 2, 840, 10045, 4, 3, 2}
  @common_name_oid {2, 5, 4, 3}

  @basic_constraints_oid {2, 5, 29, 19}
  @key_usage_oid {2, 5, 29, 15}
  @extended_key_usage_oid {2, 5, 29, 37}
  @subject_alternative_name_oid {2, 5, 29, 17}

  @server_auth_oid {1, 3, 6, 1, 5, 5, 7, 3, 1}
  @client_auth_oid {1, 3, 6, 1, 5, 5, 7, 3, 2}

  @validity_years 10
  @serial_bits 128
  @device_id_hex_length 32
  @max_certificate_der_bytes 768

  @doc "The named curve every key in the management plane is on."
  def curve_oid, do: @curve_oid

  @doc "The `id-ecPublicKey` algorithm identifier a public key must carry."
  def ec_public_key_oid, do: @ec_public_key_oid

  @doc "The signature algorithm identifier every certificate and request carries."
  def signature_oid, do: @ecdsa_with_sha256_oid

  @doc "The digest the signature is over."
  def digest, do: :sha256

  @doc "The key algorithm as it is recorded on a row."
  def key_algorithm, do: "ecdsa-p256"

  @doc "The signature algorithm as it is recorded on a row."
  def signature_algorithm, do: "ecdsa-with-sha256"

  @doc "The common-name attribute type — the only subject attribute in this profile."
  def common_name_oid, do: @common_name_oid

  @doc "How long an issued certificate is valid for, in years."
  def validity_years, do: @validity_years

  @doc "The width of a serial number, in bits."
  def serial_bits, do: @serial_bits

  @doc "How many hexadecimal characters a device identifier renders as."
  def device_id_hex_length, do: @device_id_hex_length

  @doc """
  The bound on a certificate's DER, in bytes.

  It is what an appliance can persist, and it is a hard limit rather than a
  courtesy: this profile fixes one algorithm, one curve and a subject of one
  attribute, so everything issued under it is a few hundred bytes and the bound
  is far from tight — but the appliance's state record reserves exactly this
  much, so a certificate past it is one the appliance could accept and never
  store. The issuer is where that is caught, because this is the side that can
  still do something about it: a subject long enough to exceed the bound is a
  name to shorten, and the moment to say so is before anything is signed.
  """
  @spec max_certificate_der_bytes() :: pos_integer()
  def max_certificate_der_bytes, do: @max_certificate_der_bytes

  @doc """
  Whether a string is a device identifier: 32 lowercase hexadecimal characters.

  Upper case is deliberately not accepted. A second rendering of one identity
  is two strings an administrator has to normalise before comparing, and two
  strings that will be compared carelessly.
  """
  @spec device_id?(term()) :: boolean()
  def device_id?(value) when is_binary(value) do
    byte_size(value) == @device_id_hex_length and
      value |> :binary.bin_to_list() |> Enum.all?(&hex_digit?/1)
  end

  def device_id?(_), do: false

  defp hex_digit?(byte), do: byte in ?0..?9 or byte in ?a..?f

  @doc """
  The X.509 extensions for each artifact this profile defines.

  Basic constraints and key usage are marked critical, extended key usage and
  the subject alternative name are not; that is what RFC 5280 asks of each.
  Nothing beyond these is emitted — a certificate signing request reaches none
  of it, so an issued certificate carries exactly what this function returns.
  """
  @spec extensions(:certificate_authority | :device | {:channel_endpoint, :inet.ip4_address()}) ::
          [tuple()]
  def extensions(:certificate_authority) do
    [
      {:Extension, @basic_constraints_oid, true, {:BasicConstraints, true, 0}},
      {:Extension, @key_usage_oid, true, [:keyCertSign]}
    ]
  end

  def extensions(:device) do
    [
      {:Extension, @basic_constraints_oid, true, {:BasicConstraints, false, :asn1_NOVALUE}},
      {:Extension, @key_usage_oid, true, [:digitalSignature]},
      {:Extension, @extended_key_usage_oid, false, [@client_auth_oid]}
    ]
  end

  def extensions({:channel_endpoint, {a, b, c, d}}) do
    [
      {:Extension, @basic_constraints_oid, true, {:BasicConstraints, false, :asn1_NOVALUE}},
      {:Extension, @key_usage_oid, true, [:digitalSignature]},
      {:Extension, @extended_key_usage_oid, false, [@server_auth_oid]},
      {:Extension, @subject_alternative_name_oid, false, [{:iPAddress, <<a, b, c, d>>}]}
    ]
  end
end
