defmodule Ctrld.Channel.Sessions do
  @moduledoc """
  Which appliances have a channel session open right now, and how to reach one.

  A `Registry` keyed by device identifier, one entry per live session process.
  The entry is the process, so it goes away when the session does: there is no
  clearing pass and no stale entry, which is the same property the inventory's
  `connected_since` column gets from being cleared by the listener — obtained
  here for free rather than maintained.

  ## Why a registry and not the inventory row

  The row says a session is open; it does not say which process holds it, and an
  operator staging a document needs the process. The two facts are also
  established at different moments and by different things — the row is a write,
  the entry is a registration — so an operator's action that found a row and no
  entry is an appliance that hung up between the two, which is exactly the
  refusal `stage/2` gives.

  ## Only the appliance's own session may be reached

  The key is the device identifier the *handshake* established, taken off the
  certificate this server issued and never off anything a peer sent in a frame.
  So a compromised appliance cannot register as another, and a document staged
  for one appliance cannot reach a second.

  ## Duplicate registration is a refused session and not a replaced one

  The registry is unique, so a second session for the same appliance does not
  displace the first: `register/1` answers `{:error, :already_registered}` and the
  session that could not register carries on without one. That is deliberate — an
  operator's staging in flight belongs to the connection it was sent on, and
  moving it to a connection that arrived afterwards would answer a validate
  result to whichever process happened to win a race.
  """

  @doc "The registry's name, and the child specification that starts it."
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(_options) do
    Registry.child_spec(keys: :unique, name: __MODULE__)
  end

  @doc """
  Register the calling process as `device_id`'s live session.

  Answers `{:error, :already_registered}` where a session for that appliance is
  already registered; see the module note on why that is not a takeover.
  """
  @spec register(String.t()) :: :ok | {:error, :already_registered}
  def register(device_id) when is_binary(device_id) do
    case Registry.register(__MODULE__, device_id, nil) do
      {:ok, _owner} -> :ok
      {:error, {:already_registered, _pid}} -> {:error, :already_registered}
    end
  end

  @doc "The process holding `device_id`'s session, where one is open."
  @spec whereis(String.t()) :: {:ok, pid()} | :error
  def whereis(device_id) when is_binary(device_id) do
    case Registry.lookup(__MODULE__, device_id) do
      [{pid, _value}] -> {:ok, pid}
      [] -> :error
    end
  end

  @doc """
  Ask `device_id`'s session to stage `version` on the appliance.

  A cast and not a call, and that is the whole shape of this seam: the operator's
  request returns as soon as the session has been *asked*, because what happens
  next is two frames and a round trip over a link the operator does not hold, and
  a caller waiting on it would be a web request waiting on an appliance. What the
  operator watches instead is the version's own state, which the session moves as
  the answer arrives.
  """
  @spec stage(String.t(), Ctrld.Appliances.ConfigurationVersion.t()) ::
          :ok | {:error, :no_session}
  def stage(device_id, version) when is_binary(device_id) do
    case whereis(device_id) do
      {:ok, pid} ->
        send(pid, {:stage_configuration, version})
        :ok

      :error ->
        {:error, :no_session}
    end
  end
end
