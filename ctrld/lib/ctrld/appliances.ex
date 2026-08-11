defmodule Ctrld.Appliances do
  @moduledoc """
  The appliance inventory and the onboarding that fills it.

  Onboarding is one transaction: the appliance row, its first configuration
  version, and the audit record commit together or none of them does. A
  certificate issued without a record of who issued it is exactly the fact an
  audit trail exists to hold, so it is not allowed to exist even for the width
  of a failed insert.

  It also holds what a channel session establishes about an appliance — that one
  is open, and when one was last seen — and announces every transition on
  `Ctrld.PubSub`, so a view of the inventory can be a subscription rather than a
  poll. Those two facts are the only ones a connection may write: an identity is
  the onboarding's to establish and never a session's, which is what
  `Ctrld.Appliances.Appliance.session_changeset/2` exists to enforce.
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

  A status derived from the facts on the row, never stored and never an
  optimistic default. There are three, and each is a different thing the server
  has actually observed: a session is open on this server right now, so the
  appliance is `:online`; no session is open but one was, so it is `:offline`
  with the instant beside it; or a certificate was issued and no session has
  ever opened, so it is `:onboarded` and nothing more is known.

  The order matters, and only in one direction: a live session outranks the
  memory of an ended one, because `last_seen_at` is set on both transitions and
  an online appliance therefore has both columns filled.
  """
  @spec status(Appliance.t()) :: :online | :offline | :onboarded
  def status(%Appliance{connected_since: %DateTime{}}), do: :online
  def status(%Appliance{last_seen_at: %DateTime{}}), do: :offline
  def status(%Appliance{certificate_issued_at: %DateTime{}}), do: :onboarded

  @doc """
  The topic every appliance's connection state is announced on.

  What a subscriber of this one receives, and the whole of it:

      {:appliance_connected, device_id :: String.t(), connected_since :: DateTime.t()}
      {:appliance_disconnected, device_id :: String.t(), last_seen_at :: DateTime.t()}

  Neither message carries anything an appliance sent. A subscriber that needs
  more than the transition reads the row, which is where the facts are.
  """
  @spec fleet_topic() :: String.t()
  def fleet_topic, do: "appliances"

  @doc """
  The topic one appliance's channel is announced on.

  It carries the two connection messages `fleet_topic/0` carries, so a view of
  one appliance and a view of the fleet handle the same shapes, and one more that
  the fleet topic deliberately does not:

      {:appliance_telemetry, device_id :: String.t(), ring :: :log | :capture,
       position :: non_neg_integer(), byte_count :: non_neg_integer()}

  That one arrives per upstream frame — at least once a second per appliance
  whenever it has unsent bytes — which is why it is here and not on the fleet
  topic: a view of the whole inventory would be woken by every appliance's every
  flush to render a column it does not have. `position` is the byte position in
  the recording ring's own append space that the frame's bytes began at, and
  `byte_count` is how many arrived. **The bytes themselves are not in it and
  never will be**: they are a customer's captured traffic, a recording is where
  that belongs, and a subscriber wanting content reads it from whatever ingests
  it.
  """
  @spec topic(String.t()) :: String.t()
  def topic(device_id) when is_binary(device_id), do: "appliance:" <> device_id

  @doc "Subscribe to every appliance's connection state."
  @spec subscribe() :: :ok | {:error, term()}
  def subscribe, do: Phoenix.PubSub.subscribe(Ctrld.PubSub, fleet_topic())

  @doc "Subscribe to one appliance's channel: its connection state and its traffic."
  @spec subscribe(String.t()) :: :ok | {:error, term()}
  def subscribe(device_id) when is_binary(device_id) do
    Phoenix.PubSub.subscribe(Ctrld.PubSub, topic(device_id))
  end

  @doc """
  Announce that recording bytes arrived from an appliance.

  Nothing is written: an upstream frame is not a fact about the inventory — what
  the row keeps is that a session is open, which is already true — so this is an
  announcement and only that. It is what makes a live view of one appliance's
  traffic a subscription rather than a poll, and it takes a count rather than the
  bytes because the count is all a topic may carry.
  """
  @spec telemetry_received(String.t(), :log | :capture, non_neg_integer(), non_neg_integer()) ::
          :ok
  def telemetry_received(device_id, ring, position, byte_count)
      when is_binary(device_id) and ring in [:log, :capture] and is_integer(position) and
             is_integer(byte_count) do
    Phoenix.PubSub.broadcast(
      Ctrld.PubSub,
      topic(device_id),
      {:appliance_telemetry, device_id, ring, position, byte_count}
    )

    :ok
  end

  @doc """
  Record that a channel session opened for an appliance.

  Both columns move: the session is live from `at`, and `at` is also the last
  instant the appliance was seen — so an appliance that connects and is never
  heard from again still has a last-seen instant when the session ends.
  """
  @spec session_opened(Appliance.t(), DateTime.t()) :: {:ok, Appliance.t()} | {:error, term()}
  def session_opened(%Appliance{} = appliance, %DateTime{} = at) do
    at = DateTime.truncate(at, :second)

    with {:ok, updated} <- update_session(appliance, %{connected_since: at, last_seen_at: at}) do
      announce(updated, {:appliance_connected, updated.device_id, at})
      {:ok, updated}
    end
  end

  @doc """
  Record that a channel session closed for an appliance.

  The live-session column is cleared and the last-seen instant advances, which
  together are the whole of "it was here until now and is not here".
  """
  @spec session_closed(Appliance.t(), DateTime.t()) :: {:ok, Appliance.t()} | {:error, term()}
  def session_closed(%Appliance{} = appliance, %DateTime{} = at) do
    at = DateTime.truncate(at, :second)

    with {:ok, updated} <- update_session(appliance, %{connected_since: nil, last_seen_at: at}) do
      announce(updated, {:appliance_disconnected, updated.device_id, at})
      {:ok, updated}
    end
  end

  @doc """
  Forget every live session, and answer how many were forgotten.

  Called by the channel listener as it starts. A live session is held by a
  process, so no session survives the listener that held it, and a row still
  claiming one describes a connection that cannot exist — the one way a derived
  status could lie. Nothing is announced: there is nothing subscribed at the
  instant a listener starts, and a fleet's worth of transitions nobody asked for
  is not an announcement.
  """
  @spec clear_sessions() :: non_neg_integer()
  def clear_sessions do
    {cleared, _returned} =
      Repo.update_all(
        from(appliance in Appliance, where: not is_nil(appliance.connected_since)),
        set: [connected_since: nil]
      )

    cleared
  end

  defp update_session(appliance, attributes) do
    appliance
    |> Appliance.session_changeset(attributes)
    |> Repo.update()
  end

  defp announce(appliance, message) do
    Phoenix.PubSub.broadcast(Ctrld.PubSub, fleet_topic(), message)
    Phoenix.PubSub.broadcast(Ctrld.PubSub, topic(appliance.device_id), message)
    :ok
  end

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
          certificate_issued_at: issued.issued_at,
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
