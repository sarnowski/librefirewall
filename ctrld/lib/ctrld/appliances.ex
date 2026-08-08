defmodule Ctrld.Appliances do
  @moduledoc """
  The appliance inventory and the onboarding that fills it.

  Onboarding is one transaction: the appliance row, its first configuration
  version, and the audit record commit together or none of them does. A
  certificate issued without a record of who issued it is exactly the fact an
  audit trail exists to hold, so it is not allowed to exist even for the width
  of a failed insert.
  """

  import Ecto.Query

  alias Ctrld.Appliances.{Appliance, ConfigurationVersion}
  alias Ctrld.PKI.{Certificate, CSR}
  alias Ctrld.{Audit, ChannelEndpoint, Configuration, Package, PKI, Repo}

  @doc "The inventory, newest first."
  @spec list_appliances() :: [Appliance.t()]
  def list_appliances do
    Repo.all(from(appliance in Appliance, order_by: [desc: appliance.id]))
  end

  @doc "One appliance with what a detail view shows, or nil."
  @spec get_appliance(term()) :: Appliance.t() | nil
  def get_appliance(id) do
    Repo.one(
      from(appliance in Appliance,
        where: appliance.id == ^id,
        preload: [
          :certificate_authority,
          :onboarded_by,
          configuration_versions: ^from(v in ConfigurationVersion, order_by: [desc: v.generation])
        ]
      )
    )
  end

  @doc "One appliance by the device identifier its certificate names, or nil."
  @spec get_appliance_by_device_id(String.t()) :: Appliance.t() | nil
  def get_appliance_by_device_id(device_id) when is_binary(device_id) do
    Repo.get_by(Appliance, device_id: device_id)
  end

  @doc """
  What the server can evidence about an appliance.

  A status derived from a fact the server holds, never an optimistic default:
  the request arrived and the certificate was issued, so the appliance was
  onboarded. Whether it is *reachable* is a different question, and this
  server cannot answer it until an appliance dials it.
  """
  @spec status(Appliance.t()) :: :onboarded
  def status(%Appliance{certificate_issued_at: %DateTime{}}), do: :onboarded

  @doc """
  Onboard an appliance: issue against a validated request and compose its
  package.

  Returns the appliance and the package bytes. The package is not stored — it
  is recomposed on demand from the certificate, the anchor, the endpoint and
  the document, all of which are stored, so there is one copy of each fact
  rather than two that can disagree.
  """
  @spec onboard(CSR.t(), map()) ::
          {:ok, %{appliance: Appliance.t(), package: binary()}}
          | {:error,
             atom()
             | Ecto.Changeset.t()
             | Package.reason()
             | Configuration.reason()
             | Certificate.reason()}
  def onboard(%CSR{} = request, attributes) do
    %{
      name: name,
      configuration: document,
      endpoint: %ChannelEndpoint{} = endpoint,
      actor: actor,
      received_at: %DateTime{} = received_at
    } = attributes

    now = DateTime.truncate(DateTime.utc_now(), :second)

    with :ok <- Configuration.validate(document),
         :ok <- unclaimed(request),
         {:ok, authority} <- signing_authority(),
         {:ok, issued} <-
           PKI.issue_device_certificate(authority, request.public_point, request.device_id, now) do
      appliance_changeset =
        Appliance.changeset(%Appliance{}, %{
          device_id: request.device_id,
          name: name,
          spki_fingerprint: request.spki_fingerprint,
          csr_pem: request.pem,
          csr_received_at: DateTime.truncate(received_at, :second),
          certificate_authority_id: authority.id,
          certificate_der: issued.der,
          certificate_serial: Integer.to_string(issued.serial),
          certificate_issued_at: issued.not_before,
          certificate_not_after: issued.not_after,
          endpoint: ChannelEndpoint.to_string(endpoint),
          onboarded_by_id: actor.id
        })

      Ecto.Multi.new()
      |> Ecto.Multi.insert(:appliance, appliance_changeset)
      |> Ecto.Multi.insert(:configuration_version, fn %{appliance: appliance} ->
        ConfigurationVersion.changeset(%ConfigurationVersion{}, %{
          appliance_id: appliance.id,
          generation: 1,
          document: document,
          document_sha256: ConfigurationVersion.digest(document),
          author_id: actor.id
        })
      end)
      |> Ecto.Multi.insert(:audit, fn %{appliance: appliance} ->
        Audit.record(%{
          actor_id: actor.id,
          actor_email: actor.email,
          action: "appliance.onboarded",
          subject_type: "appliance",
          subject_id: appliance.device_id,
          detail: %{
            "name" => appliance.name,
            "spki_fingerprint" => appliance.spki_fingerprint,
            "certificate_serial" => appliance.certificate_serial,
            "endpoint" => appliance.endpoint,
            "certificate_authority" => authority.subject_common_name
          }
        })
      end)
      |> Repo.transaction()
      |> case do
        {:ok, %{appliance: appliance}} -> compose(appliance, document)
        {:error, _step, reason, _changes} -> {:error, reason}
      end
    end
  end

  @doc """
  Recompose an onboarded appliance's package.

  Deterministic: the same appliance yields the same bytes, because every input
  is a stored fact and the archive's timestamps come from the issuance instant
  rather than from now.
  """
  @spec package(Appliance.t()) :: {:ok, binary()} | {:error, Package.reason()}
  def package(%Appliance{} = appliance) do
    appliance = Repo.preload(appliance, [:certificate_authority, :configuration_versions])
    # Every appliance row has at least generation 1: `onboard/2` writes the row
    # and its first configuration version in one transaction, and a version can
    # only be deleted with the appliance it belongs to.
    version = Enum.max_by(appliance.configuration_versions, & &1.generation)
    compose_bytes(appliance, version.document)
  end

  defp compose(appliance, document) do
    case compose_bytes(Repo.preload(appliance, :certificate_authority), document) do
      {:ok, bytes} -> {:ok, %{appliance: appliance, package: bytes}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp compose_bytes(appliance, document) do
    Package.build(
      %{
        device_certificate_pem: Certificate.pem(appliance.certificate_der),
        trust_anchor_pem: PKI.authority_pem(appliance.certificate_authority),
        management_endpoint: appliance.endpoint <> "\n",
        configuration_xml: document
      },
      appliance.certificate_issued_at
    )
  end

  # Nothing can be issued without an authority, and an administrator can post
  # this form at a server that has none — so it is a refusal to render rather
  # than a raise to serve a 500 with.
  defp signing_authority do
    case PKI.active_authority() do
      nil -> {:error, :no_authority}
      authority -> {:ok, authority}
    end
  end

  # One appliance, one identity. A second request carrying a device identifier
  # or a public key this server has already issued for is refused rather than
  # quietly issuing a second certificate for the same box, because the two
  # would be indistinguishable on the channel and the inventory would show one
  # appliance where there are two.
  defp unclaimed(%CSR{} = request) do
    taken =
      Repo.exists?(
        from(appliance in Appliance,
          where:
            appliance.device_id == ^request.device_id or
              appliance.spki_fingerprint == ^request.spki_fingerprint
        )
      )

    if taken, do: {:error, :already_onboarded}, else: :ok
  end

  @doc "A refusal in the words the administrator onboarding needs."
  @spec describe(:already_onboarded | :no_authority) :: String.t()
  def describe(:already_onboarded),
    do: "an appliance with this device identifier or key is already onboarded"

  def describe(:no_authority),
    do: "this server holds no certificate authority, so it can issue nothing"
end
