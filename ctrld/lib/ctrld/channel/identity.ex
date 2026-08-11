defmodule Ctrld.Channel.Identity do
  @moduledoc """
  Who an appliance is, read off the certificate it presented.

  A channel session's identity comes from the peer certificate the TLS session
  already validated against this server's own authority, and from nothing the
  appliance says afterwards. There is no frame carrying a device identifier and
  there is deliberately no room for one: an identity a peer asserts is an
  identity a peer can choose, and the certificate is the only thing here that
  a compromised appliance cannot rewrite.

  ## Adversary

  A **semi-trusted appliance**, holding a certificate this server issued. What
  it cannot do is hold one for an identifier this server did not put in a
  subject, so the whole of the check is: read the subject common name, hold it
  to the shape the certificate profile fixes, and find the appliance it names.
  An identifier of the right shape naming no row is refused rather than
  admitted as an unknown peer — a certificate whose appliance was deleted is
  precisely the case that must not become a session.

  The certificate arrives as bytes the peer sent, so the decode is guarded: a
  structure that will not parse is a refusal like any other and never an
  exception, whatever the session below made of it.
  """

  require Record

  Record.defrecordp(
    :certificate,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  Record.defrecordp(
    :tbs,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/public_key.hrl")
  )

  alias Ctrld.Appliances
  alias Ctrld.Appliances.Appliance
  alias Ctrld.PKI.Profile

  @typedoc "Why a peer's certificate does not name an appliance of this server's."
  @type refusal ::
          :no_peer_certificate
          | :peer_certificate_unreadable
          | :peer_subject_not_common_name
          | :peer_common_name_not_a_device_id
          | {:unknown_appliance, device_id :: String.t()}

  @doc """
  The device identifier a validated peer certificate's subject names.

  `:no_peer_certificate` is answered for a session with none. It should be
  unreachable — the listener requires a client certificate and fails the
  handshake without one — and it is still a value here rather than an
  assertion, because the alternative is a raise on the one path where a change
  to the listener's options would put a peer in reach of it.
  """
  @spec device_id(binary() | nil) :: {:ok, String.t()} | {:error, refusal()}
  def device_id(nil), do: {:error, :no_peer_certificate}

  def device_id(der) when is_binary(der) do
    with {:ok, subject} <- subject(der) do
      common_name(subject)
    end
  end

  @doc """
  The appliance a validated peer certificate names.

  Both halves in one step, because a session has no use for either alone: an
  identifier without a row is a connection to refuse, and a row is what every
  later decision on the session is made against.
  """
  @spec appliance(binary() | nil) :: {:ok, String.t(), Appliance.t()} | {:error, refusal()}
  def appliance(der) do
    with {:ok, device_id} <- device_id(der) do
      case Appliances.get_appliance_by_device_id(device_id) do
        %Appliance{} = appliance -> {:ok, device_id, appliance}
        nil -> {:error, {:unknown_appliance, device_id}}
      end
    end
  end

  @doc "A refusal in the words an operator reading the log needs."
  @spec describe(refusal()) :: String.t()
  def describe(:no_peer_certificate), do: "the session carries no client certificate"

  def describe(:peer_certificate_unreadable),
    do: "the client certificate does not decode as an X.509 certificate"

  def describe(:peer_subject_not_common_name),
    do: "the client certificate's subject is not one common name"

  def describe(:peer_common_name_not_a_device_id),
    do: "the client certificate's common name is not a device identifier"

  def describe({:unknown_appliance, _device_id}),
    do: "the client certificate names no appliance this server has onboarded"

  defp subject(der) do
    case safely(fn -> :public_key.pkix_decode_cert(der, :otp) end) do
      {:ok, certificate(tbsCertificate: tbs(subject: subject))} -> {:ok, subject}
      _other -> {:error, :peer_certificate_unreadable}
    end
  end

  # The profile fixes a subject of exactly one common name, so anything else is
  # refused rather than searched for a common name among other attributes: a
  # certificate carrying two is not one this server issued.
  defp common_name({:rdnSequence, [[{:AttributeTypeAndValue, oid, {:utf8String, name}}]]})
       when is_binary(name) do
    if oid == Profile.common_name_oid() do
      device_id_shaped(name)
    else
      {:error, :peer_subject_not_common_name}
    end
  end

  defp common_name(_other), do: {:error, :peer_subject_not_common_name}

  defp device_id_shaped(name) do
    if Profile.device_id?(name),
      do: {:ok, name},
      else: {:error, :peer_common_name_not_a_device_id}
  end

  defp safely(function) do
    {:ok, function.()}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end
end
