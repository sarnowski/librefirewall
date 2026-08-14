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

  ## Changing an appliance's configuration

  And it drives the configuration transaction, which is the one thing an
  administrator does to an appliance that takes more than one step and more than
  one connection. `stage_configuration/3` writes the version and asks the live
  session to send it; the session reports the appliance's verdict back through
  `configuration_validated/4`, commits through `configuration_committed/3`, and
  confirms over the *next* connection through `configuration_confirmed/3`.

  **Every step is one transaction with its own audit record**, on the onboarding's
  reasoning exactly: a configuration that reached an appliance without a record of
  who sent it is the fact an audit trail exists to hold. The three steps the
  session drives carry no actor, because no administrator was there — the audit
  record names the appliance's own channel as the actor, which is what actually
  did it.
  """

  import Ecto.Query

  alias Ctrld.Appliances.{Appliance, ConfigurationVersion}
  alias Ctrld.Channel.Sessions
  alias Ctrld.PKI.{Certificate, CSR}
  alias Ctrld.{Audit, ChannelEndpoint, Configuration, Package, PKI, Repo}

  # The actor an audit record names for the three steps no administrator is
  # present for. A name and not a user reference: the channel is not a user, and
  # a record that borrowed the staging administrator's identity would say they
  # confirmed a commit they may have been asleep for.
  @channel_actor "the appliance's own channel"

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

  And one more, for each step a configuration transaction takes:

      {:appliance_configuration, device_id :: String.t(), generation :: pos_integer(),
       state :: Ctrld.Appliances.ConfigurationVersion.state()}

  Here for the same reason: a change is watched on the page of the appliance it
  is being made to. It carries the derived state and not the appliance's result
  line, so a subscriber renders a transition and reads the row for the verdict.
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

  @doc """
  Stage `document` on `appliance` as its next generation.

  The version row and its audit record commit together, and only then is the live
  session asked to send the document down the channel. That order is deliberate:
  a document that reached an appliance with no record of who sent it is the one
  thing this trail exists to prevent, so the record is durable before a byte
  leaves — and a session that hung up in between leaves a version in `:staging`,
  which is an honest description of what happened rather than a lost change.

  Refused where this server can refuse it. The document is held to
  `Ctrld.Configuration` first, because a document this server can already tell is
  wrong should not cost an appliance a round trip; the appliance's own validator
  is still the authority, and its verdict is what the version records.
  `{:error, :no_session}` is the refusal an operator gets for an appliance that is
  not connected — there is no queue behind it, because a configuration held for an
  appliance that reappears in a fortnight is a change nobody remembers asking for.
  """
  @spec stage_configuration(Appliance.t(), binary(), Ctrld.Accounts.User.t()) ::
          {:ok, ConfigurationVersion.t()}
          | {:error, :no_session | :in_flight | Configuration.reason() | Ecto.Changeset.t()}
  def stage_configuration(%Appliance{} = appliance, document, actor) when is_binary(document) do
    with :ok <- Configuration.validate(document),
         :ok <- nothing_in_flight(appliance),
         {:ok, version} <- insert_staged(appliance, document, actor) do
      case Sessions.stage(appliance.device_id, version) do
        :ok ->
          announce_configuration(appliance.device_id, version)
          {:ok, version}

        # The row and its audit record stay: the change was authorised and
        # recorded, and the appliance was gone. Reporting it as though nothing
        # had happened would leave an operator a trail with a hole in it.
        {:error, :no_session} ->
          announce_configuration(appliance.device_id, version)
          {:error, :no_session}
      end
    end
  end

  @doc """
  Record the appliance's verdict on the document it was sent.

  `line` is the appliance's own result line, stored verbatim: it names the rule
  that refused a document and the offset that places it, and this server has no
  business paraphrasing a verdict it did not reach.
  """
  @spec configuration_validated(String.t(), pos_integer(), String.t(), DateTime.t()) ::
          {:ok, ConfigurationVersion.t()} | {:error, :no_such_version | Ecto.Changeset.t()}
  def configuration_validated(device_id, generation, line, %DateTime{} = at)
      when is_binary(device_id) and is_integer(generation) and is_binary(line) do
    advance(device_id, generation, %{
      validated_at: DateTime.truncate(at, :second),
      validation_result: line
    })
  end

  @doc """
  Record that this server committed `generation` provisionally.

  There is no acknowledgement to wait for and none to record: the appliance ends
  the session on a commit, which is how the protocol makes the confirmation
  arrive over a fresh connection. So what this writes is the send, and what
  evidences the commit landing is the appliance coming back at all.
  """
  @spec configuration_committed(String.t(), pos_integer(), DateTime.t()) ::
          {:ok, ConfigurationVersion.t()} | {:error, :no_such_version | Ecto.Changeset.t()}
  def configuration_committed(device_id, generation, %DateTime{} = at)
      when is_binary(device_id) and is_integer(generation) do
    advance(device_id, generation, %{committed_at: DateTime.truncate(at, :second)})
  end

  @doc "Record that this server confirmed `generation` over a fresh connection."
  @spec configuration_confirmed(String.t(), pos_integer(), DateTime.t()) ::
          {:ok, ConfigurationVersion.t()} | {:error, :no_such_version | Ecto.Changeset.t()}
  def configuration_confirmed(device_id, generation, %DateTime{} = at)
      when is_binary(device_id) and is_integer(generation) do
    advance(device_id, generation, %{confirmed_at: DateTime.truncate(at, :second)})
  end

  @doc """
  The version this appliance owes a confirmation, where it owes one.

  A commit with no confirmation, newest first. There is at most one — a stage is
  refused while another version is in flight — and the query is written for the
  general case anyway, because "at most one" is a rule of this module and not of
  the table.
  """
  @spec awaiting_confirmation(String.t()) :: ConfigurationVersion.t() | nil
  def awaiting_confirmation(device_id) when is_binary(device_id) do
    Repo.one(
      from(version in ConfigurationVersion,
        join: appliance in assoc(version, :appliance),
        where:
          appliance.device_id == ^device_id and not is_nil(version.committed_at) and
            is_nil(version.confirmed_at),
        order_by: [desc: version.generation],
        limit: 1
      )
    )
  end

  @doc """
  The version an appliance's next generation number follows, as that number.

  The appliance's datastore is the real authority on it — a commit names a
  generation and the appliance refuses one that is not the number it would
  assign — so this is the number this server *proposes*, and the result line is
  where the appliance says what it actually is.
  """
  @spec next_generation(Appliance.t()) :: pos_integer()
  def next_generation(%Appliance{} = appliance) do
    highest =
      Repo.one(
        from(version in ConfigurationVersion,
          where: version.appliance_id == ^appliance.id,
          select: max(version.generation)
        )
      )

    (highest || 0) + 1
  end

  # One configuration transaction at a time per appliance. A second stage while
  # one is in flight is refused rather than queued: the appliance holds ONE
  # candidate, so a second staged document would displace the first on the
  # appliance while this server still showed both, and a commit would then name a
  # generation whose document is not the one an operator is looking at.
  defp nothing_in_flight(%Appliance{} = appliance) do
    in_flight =
      Repo.exists?(
        from(version in ConfigurationVersion,
          where:
            version.appliance_id == ^appliance.id and not is_nil(version.staged_at) and
              is_nil(version.confirmed_at) and
              (is_nil(version.validated_at) or not is_nil(version.committed_at))
        )
      )

    if in_flight, do: {:error, :in_flight}, else: :ok
  end

  defp insert_staged(%Appliance{} = appliance, document, actor) do
    now = DateTime.truncate(DateTime.utc_now(), :second)
    generation = next_generation(appliance)

    Ecto.Multi.new()
    |> Ecto.Multi.insert(
      :version,
      ConfigurationVersion.changeset(%ConfigurationVersion{}, %{
        appliance_id: appliance.id,
        generation: generation,
        document: document,
        document_sha256: ConfigurationVersion.digest(document),
        author_id: actor.id,
        staged_at: now
      })
    )
    |> Ecto.Multi.insert(
      :audit,
      Audit.record(%{
        actor_id: actor.id,
        actor_email: actor.email,
        action: "configuration.staged",
        subject_type: "appliance",
        subject_id: appliance.device_id,
        detail: %{
          "generation" => generation,
          "document_sha256" => ConfigurationVersion.digest(document)
        }
      })
    )
    |> Repo.transaction()
    |> case do
      {:ok, %{version: version}} -> {:ok, version}
      {:error, _step, reason, _changes} -> {:error, reason}
    end
  end

  # One step of the transaction, with the audit record that names it, in one
  # database transaction. The action is derived from the attribute that moved, so
  # a step cannot be recorded under another step's name.
  defp advance(device_id, generation, attributes) do
    case version_of(device_id, generation) do
      nil ->
        {:error, :no_such_version}

      version ->
        Ecto.Multi.new()
        |> Ecto.Multi.update(:version, ConfigurationVersion.changeset(version, attributes))
        |> Ecto.Multi.insert(
          :audit,
          Audit.record(%{
            actor_email: @channel_actor,
            action: step_action(attributes),
            subject_type: "appliance",
            subject_id: device_id,
            detail: step_detail(generation, attributes)
          })
        )
        |> Repo.transaction()
        |> case do
          {:ok, %{version: updated}} ->
            announce_configuration(device_id, updated)
            {:ok, updated}

          {:error, _step, reason, _changes} ->
            {:error, reason}
        end
    end
  end

  defp step_action(%{validated_at: _at, validation_result: line}) do
    if ConfigurationVersion.accepted?(line),
      do: "configuration.staged_on_appliance",
      else: "configuration.refused_by_appliance"
  end

  defp step_action(%{committed_at: _at}), do: "configuration.committed"
  defp step_action(%{confirmed_at: _at}), do: "configuration.confirmed"

  defp step_detail(generation, %{validation_result: line}),
    do: %{"generation" => generation, "result" => line}

  defp step_detail(generation, _attributes), do: %{"generation" => generation}

  defp version_of(device_id, generation) do
    Repo.one(
      from(version in ConfigurationVersion,
        join: appliance in assoc(version, :appliance),
        where: appliance.device_id == ^device_id and version.generation == ^generation
      )
    )
  end

  # A configuration step is announced on the appliance's own topic and not on the
  # fleet's, on `telemetry_received/4`'s reasoning: a view of the whole inventory
  # has no column for it and would be woken to render nothing.
  defp announce_configuration(device_id, %ConfigurationVersion{} = version) do
    Phoenix.PubSub.broadcast(
      Ctrld.PubSub,
      topic(device_id),
      {:appliance_configuration, device_id, version.generation,
       ConfigurationVersion.state(version)}
    )

    :ok
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

  @doc "A refusal in the words the administrator onboarding or staging needs."
  @spec describe(:already_onboarded | :no_authority | :no_session | :in_flight) :: String.t()
  def describe(:already_onboarded),
    do: "an appliance with this device identifier or key is already onboarded"

  def describe(:no_authority),
    do: "this server holds no certificate authority, so it can issue nothing"

  def describe(:no_session),
    do:
      "the appliance has no channel session open, so there is nothing to stage a document on; " <>
        "the version is recorded and can be staged again once it dials in"

  def describe(:in_flight),
    do:
      "a configuration change for this appliance is still in flight; an appliance holds one " <>
        "candidate, so the one in progress has to finish before another is staged"
end
