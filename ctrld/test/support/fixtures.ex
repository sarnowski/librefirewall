defmodule Ctrld.Fixtures do
  @moduledoc """
  The things a test needs to have already happened.

  Every key and every certificate here is generated inside the test that uses
  it. Nothing key-shaped is committed to this repository, so there is no
  fixture that could be mistaken for a real credential and none that could
  quietly become one.
  """

  alias Ctrld.PKI.{Certificate, KeyPair, Profile}
  alias Ctrld.{Accounts, ChannelEndpoint, PKI}

  @doc "An administrator account."
  def administrator_fixture(attributes \\ %{}) do
    address = "admin-#{System.unique_integer([:positive])}@librefirewall.invalid"

    {:ok, user} =
      Accounts.create_user(
        Enum.into(attributes, %{
          email: address,
          password: "a-long-enough-password",
          role: "administrator"
        })
      )

    user
  end

  @doc "The signing authority."
  def authority_fixture(name \\ "test authority") do
    {:ok, authority} = PKI.create_authority(name)
    authority
  end

  @doc "The channel endpoint this deployment was configured with."
  def endpoint_fixture, do: ChannelEndpoint.configured!()

  @doc "The channel endpoint's server certificate, and the authority under it."
  def endpoint_certificate_fixture(endpoint \\ nil) do
    _authority = PKI.active_authority() || authority_fixture()
    {:ok, certificate} = PKI.issue_endpoint_certificate(endpoint || endpoint_fixture())
    certificate
  end

  @doc """
  A loopback endpoint, for a listener a test can actually reach.

  The configured endpoint is an address literal a fleet dials and nothing in a
  gate container answers on it, so a test that wants a real connection issues
  the endpoint certificate for this one instead. The port is not in the
  certificate — the profile binds the address and only the address, an appliance
  validating what it dialled rather than where — so a certificate issued here is
  valid for whichever port the operating system then hands the listener.
  """
  def loopback_endpoint, do: %ChannelEndpoint{address: {127, 0, 0, 1}, port: 1}

  @doc """
  A device certificate under this server's own authority, with its private key.

  The client half of a channel handshake. `device_id` decides whether it names
  an onboarded appliance: pass an onboarded one's to be admitted, and a fresh
  one to be a certificate this server issued that names nothing it holds.
  """
  def device_certificate_fixture(device_id) when is_binary(device_id) do
    authority = PKI.active_authority() || authority_fixture()
    key = KeyPair.generate()

    {:ok, issued} =
      PKI.issue_device_certificate(
        authority,
        KeyPair.public_point(key),
        device_id,
        DateTime.utc_now()
      )

    %{device_id: device_id, der: issued.der, key: key}
  end

  @doc """
  A device certificate under an authority this server has never heard of.

  Generated in memory and inserted nowhere, which is the point twice over: it is
  a credential no row of this server's backs, and creating a second authority row
  would leave the server with two it considers active.
  """
  def foreign_device_certificate_fixture(device_id \\ nil) do
    device_id = device_id || device_id()
    now = DateTime.utc_now()
    {:ok, {authority, authority_key}} = Certificate.create_authority("foreign authority", now)
    key = KeyPair.generate()

    {:ok, issued} =
      Certificate.issue_under(
        :device,
        device_id,
        KeyPair.public_point(key),
        authority.subject_common_name,
        authority_key,
        now
      )

    %{device_id: device_id, der: issued.der, key: key, authority_der: authority.der}
  end

  @doc "A random device identifier, rendered the way the profile renders one."
  def device_id do
    :crypto.strong_rand_bytes(div(Profile.device_id_hex_length(), 2))
    |> Base.encode16(case: :lower)
  end

  @doc """
  A certificate signing request of the shape the appliance produces.

  Built here rather than committed, and built from the same primitives the
  server validates with — which is why the suite also holds a request produced
  by `openssl` to the same profile: two independent producers agreeing is the
  evidence, one producer agreeing with itself is not.
  """
  def csr_fixture(options \\ []) do
    key = Keyword.get_lazy(options, :key, &KeyPair.generate/0)
    subject = Keyword.get_lazy(options, :subject, &device_id/0)
    attributes = Keyword.get(options, :attributes, [])
    digest = Keyword.get(options, :digest, Profile.digest())

    {:ok, pem} = build_request(key, subject, attributes, digest)
    %{pem: pem, key: key, device_id: subject}
  end

  @doc "The PEM of a request built from the parts, for the negative cases."
  def build_request(key, subject, attributes, digest) do
    point = KeyPair.public_point(key)

    info =
      {:CertificationRequestInfo, :v1,
       {:rdnSequence,
        [
          [
            {:AttributeTypeAndValue, Profile.common_name_oid(),
             :public_key.der_encode(:X520CommonName, {:utf8String, subject})}
          ]
        ]},
       {:CertificationRequestInfo_subjectPKInfo,
        {:CertificationRequestInfo_subjectPKInfo_algorithm, Profile.ec_public_key_oid(),
         {:asn1_OPENTYPE,
          :public_key.der_encode(:EcpkParameters, {:namedCurve, Profile.curve_oid()})}}, point},
       attributes}

    signature =
      :public_key.sign(:public_key.der_encode(:CertificationRequestInfo, info), digest, key)

    der =
      :public_key.der_encode(
        :CertificationRequest,
        {:CertificationRequest, info,
         {:CertificationRequest_signatureAlgorithm, Profile.signature_oid(), :asn1_NOVALUE},
         signature}
      )

    {:ok, :public_key.pem_encode([{:CertificationRequest, der, :not_encrypted}])}
  end

  @doc """
  A request built around an RSA key, for the profile's algorithm refusals.

  `sign_with` chooses which refusal it reaches: `:rsa` signs it the way an
  RSA request really would be, so the signature algorithm is refused first;
  `:profile` claims this profile's signature algorithm over an RSA key, which
  is what gets past that check and onto the key one.
  """
  def rsa_csr_fixture(sign_with) do
    key = :public_key.generate_key({:rsa, 2048, 65_537})
    {:RSAPrivateKey, _, modulus, exponent, _, _, _, _, _, _, _} = key
    subject = device_id()

    algorithm =
      case sign_with do
        :rsa -> {1, 2, 840, 113_549, 1, 1, 11}
        :profile -> Profile.signature_oid()
      end

    info =
      {:CertificationRequestInfo, :v1,
       {:rdnSequence,
        [
          [
            {:AttributeTypeAndValue, Profile.common_name_oid(),
             :public_key.der_encode(:X520CommonName, {:utf8String, subject})}
          ]
        ]},
       {:CertificationRequestInfo_subjectPKInfo,
        {:CertificationRequestInfo_subjectPKInfo_algorithm, {1, 2, 840, 113_549, 1, 1, 1},
         {:asn1_OPENTYPE, <<5, 0>>}},
        :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, modulus, exponent})}, []}

    signature =
      :public_key.sign(:public_key.der_encode(:CertificationRequestInfo, info), :sha256, key)

    der =
      :public_key.der_encode(
        :CertificationRequest,
        {:CertificationRequest, info,
         {:CertificationRequest_signatureAlgorithm, algorithm, :asn1_NOVALUE}, signature}
      )

    :public_key.pem_encode([{:CertificationRequest, der, :not_encrypted}])
  end

  @doc "A request whose subject carries something other than one common name."
  def odd_subject_csr_fixture(subject) do
    key = KeyPair.generate()
    point = KeyPair.public_point(key)

    info =
      {:CertificationRequestInfo, :v1, subject,
       {:CertificationRequestInfo_subjectPKInfo,
        {:CertificationRequestInfo_subjectPKInfo_algorithm, Profile.ec_public_key_oid(),
         {:asn1_OPENTYPE,
          :public_key.der_encode(:EcpkParameters, {:namedCurve, Profile.curve_oid()})}}, point},
       []}

    signature =
      :public_key.sign(
        :public_key.der_encode(:CertificationRequestInfo, info),
        Profile.digest(),
        key
      )

    der =
      :public_key.der_encode(
        :CertificationRequest,
        {:CertificationRequest, info,
         {:CertificationRequest_signatureAlgorithm, Profile.signature_oid(), :asn1_NOVALUE},
         signature}
      )

    :public_key.pem_encode([{:CertificationRequest, der, :not_encrypted}])
  end

  @doc """
  An onboarded appliance, with the package it was issued.

  The private key behind its certificate comes back too, under `:key`: a test
  that dials the channel as this appliance needs the key its certificate binds,
  and generating a second one would be presenting a certificate for a key the
  client cannot prove it holds.
  """
  def onboarded_fixture(options \\ []) do
    actor = Keyword.get_lazy(options, :actor, &administrator_fixture/0)
    _authority = PKI.active_authority() || authority_fixture()
    request = csr_fixture()
    {:ok, parsed} = Ctrld.PKI.CSR.parse(request.pem)

    {:ok, result} =
      Ctrld.Appliances.onboard(parsed, %{
        name: Keyword.get(options, :name, "appliance-#{System.unique_integer([:positive])}"),
        configuration: Keyword.get_lazy(options, :configuration, &Ctrld.Configuration.template/0),
        endpoint: endpoint_fixture(),
        actor: actor,
        received_at: DateTime.truncate(DateTime.utc_now(), :second)
      })

    result |> Map.put(:actor, actor) |> Map.put(:key, request.key)
  end
end
