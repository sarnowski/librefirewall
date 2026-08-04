defmodule Ctrld.PKI.CSR do
  @moduledoc """
  Reading a PKCS#10 certificate signing request an administrator uploaded.

  This is the server's external-input path: the bytes arrive over the web
  interface, and the only thing known about them before they are parsed is
  their length. So the work is bounded before it starts, every decoder is
  wrapped, and every refusal is a named reason rather than a raise, a `nil`,
  or a partially accepted request — the caller has to tell the administrator
  what was wrong with the file they chose.

  What is accepted is exactly what the profile describes and nothing wider: an
  ECDSA P-256 request signed with SHA-256, carrying one subject attribute that
  is a device identifier, requesting nothing. A request that asks for an
  extension is refused rather than accepted and ignored, because a request
  that appears to have been honoured and was not is worse than one that was
  turned away.
  """

  alias Ctrld.PKI.{KeyPair, Profile}

  @maximum_bytes 16 * 1024

  @enforce_keys [:device_id, :public_point, :spki_fingerprint, :pem]
  defstruct [:device_id, :public_point, :spki_fingerprint, :pem]

  @type t :: %__MODULE__{
          device_id: String.t(),
          public_point: binary(),
          spki_fingerprint: String.t(),
          pem: String.t()
        }

  @type reason ::
          {:too_large, pos_integer()}
          | :not_pem
          | :wrong_pem_label
          | :multiple_pem_entries
          | :malformed
          | {:unsupported_version, term()}
          | {:unsupported_signature_algorithm, tuple()}
          | {:unsupported_key_algorithm, tuple()}
          | {:unsupported_curve, term()}
          | :subject_not_one_attribute
          | :subject_not_common_name
          | :common_name_not_a_device_id
          | :requests_extensions
          | :bad_signature

  @doc "The largest request this server will read, in bytes."
  @spec maximum_bytes() :: pos_integer()
  def maximum_bytes, do: @maximum_bytes

  @doc """
  Parse and validate an uploaded request.

  The length bound is applied to the raw upload before anything looks at it,
  so a large file costs a comparison rather than a parse.
  """
  @spec parse(binary()) :: {:ok, t()} | {:error, reason()}
  def parse(uploaded) when is_binary(uploaded) do
    if byte_size(uploaded) > @maximum_bytes do
      {:error, {:too_large, byte_size(uploaded)}}
    else
      with {:ok, der} <- decapsulate(uploaded),
           {:ok, request} <- decode(der),
           {:ok, info, signature} <- validate_signature_algorithm(request),
           {:ok, point} <- public_point(info),
           {:ok, device_id} <- device_id(info),
           :ok <- no_attributes(info),
           :ok <- verify(info, signature, point) do
        {:ok,
         %__MODULE__{
           device_id: device_id,
           public_point: point,
           spki_fingerprint: KeyPair.fingerprint(point),
           pem: :public_key.pem_encode([{:CertificationRequest, der, :not_encrypted}])
         }}
      end
    end
  end

  @doc "A refusal in the words an administrator reading the upload form needs."
  @spec describe(reason()) :: String.t()
  def describe({:too_large, size}),
    do:
      "the file is #{size} bytes; a certificate signing request may be at most #{@maximum_bytes}"

  def describe(:not_pem), do: "the file is not PEM"

  def describe(:wrong_pem_label),
    do: "the file is PEM but does not hold a CERTIFICATE REQUEST"

  def describe(:multiple_pem_entries),
    do: "the file holds more than one PEM structure; it must hold exactly one request"

  def describe(:malformed), do: "the request is not a well-formed PKCS#10 structure"

  def describe({:unsupported_version, version}),
    do: "the request states version #{inspect(version)}; only PKCS#10 version 1 is accepted"

  def describe({:unsupported_signature_algorithm, oid}),
    do: "the request is signed with #{oid_text(oid)}; this profile is ECDSA with SHA-256"

  def describe({:unsupported_key_algorithm, oid}),
    do: "the request carries a #{oid_text(oid)} key; this profile is ECDSA on P-256"

  def describe({:unsupported_curve, curve}),
    do: "the request's key is on #{inspect(curve)}; this profile is P-256"

  def describe(:subject_not_one_attribute),
    do: "the subject carries more than a common name; a device identity has no other attribute"

  def describe(:subject_not_common_name), do: "the subject's one attribute is not a common name"

  def describe(:common_name_not_a_device_id),
    do:
      "the common name is not a device identifier: it must be #{Profile.device_id_hex_length()} lowercase hexadecimal characters"

  def describe(:requests_extensions),
    do:
      "the request asks for certificate extensions; this authority honours none, so a request carrying them is refused rather than silently ignored"

  def describe(:bad_signature),
    do: "the request's signature does not verify against the key it carries"

  defp oid_text(oid), do: Enum.join(Tuple.to_list(oid), ".")

  defp decapsulate(uploaded) do
    case safely(fn -> :public_key.pem_decode(uploaded) end) do
      {:ok, [{:CertificationRequest, der, :not_encrypted}]} -> {:ok, der}
      {:ok, [{_other, _der, _}]} -> {:error, :wrong_pem_label}
      {:ok, []} -> {:error, :not_pem}
      {:ok, _many} -> {:error, :multiple_pem_entries}
      :error -> {:error, :not_pem}
    end
  end

  defp decode(der) do
    case safely(fn -> :public_key.der_decode(:CertificationRequest, der) end) do
      {:ok, {:CertificationRequest, _info, _algorithm, _signature} = request} -> {:ok, request}
      _other -> {:error, :malformed}
    end
  end

  defp validate_signature_algorithm({:CertificationRequest, info, algorithm, signature}) do
    expected = Profile.signature_oid()

    case algorithm do
      {:CertificationRequest_signatureAlgorithm, ^expected, _parameters} ->
        validate_version(info, signature)

      {:CertificationRequest_signatureAlgorithm, other, _parameters} ->
        {:error, {:unsupported_signature_algorithm, other}}

      _other ->
        {:error, :malformed}
    end
  end

  defp validate_version({:CertificationRequestInfo, :v1, _, _, _} = info, signature),
    do: {:ok, info, signature}

  defp validate_version({:CertificationRequestInfo, version, _, _, _}, _signature),
    do: {:error, {:unsupported_version, version}}

  defp validate_version(_info, _signature), do: {:error, :malformed}

  defp public_point({:CertificationRequestInfo, _v, _subject, key_info, _attributes}) do
    expected_algorithm = Profile.ec_public_key_oid()
    expected_curve = Profile.curve_oid()

    case key_info do
      {:CertificationRequestInfo_subjectPKInfo,
       {:CertificationRequestInfo_subjectPKInfo_algorithm, ^expected_algorithm, parameters},
       point}
      when is_binary(point) ->
        case named_curve(parameters) do
          {:ok, ^expected_curve} -> {:ok, point}
          {:ok, other} -> {:error, {:unsupported_curve, other}}
          :error -> {:error, :malformed}
        end

      {:CertificationRequestInfo_subjectPKInfo,
       {:CertificationRequestInfo_subjectPKInfo_algorithm, other, _parameters}, _point} ->
        {:error, {:unsupported_key_algorithm, other}}

      _other ->
        {:error, :malformed}
    end
  end

  defp named_curve({:asn1_OPENTYPE, der}), do: decode_curve(der)
  defp named_curve(der) when is_binary(der), do: decode_curve(der)
  defp named_curve(_other), do: :error

  defp decode_curve(der) do
    case safely(fn -> :public_key.der_decode(:EcpkParameters, der) end) do
      {:ok, {:namedCurve, curve}} -> {:ok, curve}
      {:ok, other} -> {:ok, other}
      :error -> :error
    end
  end

  defp device_id({:CertificationRequestInfo, _v, subject, _key_info, _attributes}) do
    expected = Profile.common_name_oid()

    case subject do
      {:rdnSequence, [[{:AttributeTypeAndValue, ^expected, value}]]} ->
        common_name(value)

      {:rdnSequence, [[{:AttributeTypeAndValue, _other, _value}]]} ->
        {:error, :subject_not_common_name}

      {:rdnSequence, _many} ->
        {:error, :subject_not_one_attribute}

      _other ->
        {:error, :malformed}
    end
  end

  defp common_name(value) when is_binary(value) do
    case safely(fn -> :public_key.der_decode(:X520CommonName, value) end) do
      {:ok, {_string_type, name}} -> check_device_id(to_string(name))
      :error -> {:error, :malformed}
    end
  end

  defp common_name(_other), do: {:error, :malformed}

  defp check_device_id(name) do
    if Profile.device_id?(name), do: {:ok, name}, else: {:error, :common_name_not_a_device_id}
  end

  defp no_attributes({:CertificationRequestInfo, _v, _subject, _key_info, []}), do: :ok

  defp no_attributes({:CertificationRequestInfo, _v, _s, _k, list}) when is_list(list),
    do: {:error, :requests_extensions}

  defp no_attributes(_other), do: {:error, :malformed}

  defp verify(info, signature, point) when is_binary(signature) do
    key = {{:ECPoint, point}, {:namedCurve, Profile.curve_oid()}}

    result =
      safely(fn ->
        :public_key.verify(
          :public_key.der_encode(:CertificationRequestInfo, info),
          Profile.digest(),
          signature,
          key
        )
      end)

    case result do
      {:ok, true} -> :ok
      _other -> {:error, :bad_signature}
    end
  end

  defp verify(_info, _signature, _point), do: {:error, :malformed}

  # Every ASN.1 decoder here is reading bytes chosen by whoever uploaded them,
  # and the OTP decoders raise, exit, and throw on malformed input rather than
  # returning. One wrapper turns all three into the refusal the caller has to
  # render.
  defp safely(function) do
    {:ok, function.()}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end
end
