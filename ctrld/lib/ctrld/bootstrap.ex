defmodule Ctrld.Bootstrap do
  @moduledoc """
  What the server puts in place the first time it starts against an empty
  database: an administrator, a certificate authority, and the channel
  endpoint's server certificate.

  Every step is idempotent and every step is evidence-driven — it looks at
  what is there and creates only what is not — so a restart is a no-operation
  and a half-finished first start completes on the next one.

  The administrator's password comes from the environment and is never
  generated and printed. A generated password has to be shown somewhere to be
  usable, and the only surfaces this server has are ones a secret must not
  reach; requiring it in the environment keeps the secret in the place the
  deployment already keeps its other ones.
  """

  require Logger

  alias Ctrld.{Accounts, Audit, ChannelEndpoint, PKI}

  @doc "Run every step, in order. Returns the actions it actually took."
  @spec run() :: {:ok, [atom()]} | {:error, term()}
  def run do
    with {:ok, administrator} <- ensure_administrator(),
         {:ok, authority} <- ensure_authority(),
         {:ok, endpoint} <- ensure_endpoint_certificate() do
      {:ok, Enum.reject([administrator, authority, endpoint], &is_nil/1)}
    end
  end

  @doc "Whether the application should bootstrap as part of starting."
  @spec run_on_start?() :: boolean()
  def run_on_start?, do: settings()[:run_on_start] == true

  @doc false
  def child_spec(_arguments) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, [[]]}, restart: :temporary, type: :worker}
  end

  @doc """
  Run as a supervised step rather than as a process.

  Returning `:ignore` leaves no child behind, and returning an error aborts
  the supervisor's start — which is how a failed bootstrap becomes a server
  that did not come up rather than one that came up unusable.
  """
  @spec start_link(keyword()) :: :ignore | {:error, term()}
  def start_link(_arguments) do
    case run() do
      {:ok, _taken} -> :ignore
      {:error, reason} -> {:error, reason}
    end
  end

  defp ensure_administrator do
    if Accounts.count_users() > 0 do
      {:ok, nil}
    else
      create_administrator(settings()[:administrator_email], settings()[:administrator_password])
    end
  end

  defp create_administrator(email, password)
       when is_binary(email) and is_binary(password) and email != "" and password != "" do
    case Accounts.create_user(%{email: email, password: password, role: "administrator"}) do
      {:ok, user} ->
        Audit.write!(%{
          actor_id: user.id,
          actor_email: user.email,
          action: "user.bootstrapped",
          subject_type: "user",
          subject_id: user.email,
          detail: %{"role" => user.role}
        })

        Logger.info("ctrld: bootstrapped the administrator account #{user.email}")
        {:ok, :administrator}

      {:error, changeset} ->
        {:error, {:administrator, changeset}}
    end
  end

  defp create_administrator(_email, _password) do
    {:error,
     "the database holds no account and CTRLD_ADMIN_EMAIL or CTRLD_ADMIN_PASSWORD is not set; " <>
       "the first administrator's credentials come from the environment and are never generated"}
  end

  defp ensure_authority do
    case PKI.active_authority() do
      nil ->
        name = Application.get_env(:ctrld, Ctrld.PKI, [])[:authority_name]

        case PKI.create_authority(name) do
          {:ok, authority} ->
            Logger.info(
              "ctrld: created the management certificate authority #{authority.subject_common_name} " <>
                "(SPKI #{authority.spki_fingerprint})"
            )

            {:ok, :certificate_authority}

          {:error, {:certificate_too_long, _, _, _} = reason} ->
            {:error, {:certificate_authority, PKI.Certificate.describe(reason)}}

          {:error, changeset} ->
            {:error, {:certificate_authority, changeset}}
        end

      _existing ->
        {:ok, nil}
    end
  end

  # The endpoint certificate has to name the endpoint appliances are being told
  # to dial. If the configured endpoint has moved, the certificate for the old
  # one is retired and a new one issued — a certificate for an address this
  # server no longer answers on is worse than none, because it looks current.
  defp ensure_endpoint_certificate do
    configured = ChannelEndpoint.configured!()
    rendered = ChannelEndpoint.to_string(configured)

    case PKI.active_endpoint_certificate() do
      %{endpoint: ^rendered} ->
        {:ok, nil}

      nil ->
        issue_endpoint(configured, rendered)

      _stale ->
        reissue_endpoint(configured, rendered)
    end
  end

  defp issue_endpoint(configured, rendered) do
    case PKI.issue_endpoint_certificate(configured) do
      {:ok, _certificate} ->
        Logger.info("ctrld: issued the channel endpoint certificate for #{rendered}")
        {:ok, :endpoint_certificate}

      {:error, {:certificate_too_long, _, _, _} = reason} ->
        {:error, {:endpoint_certificate, PKI.Certificate.describe(reason)}}

      {:error, changeset} ->
        {:error, {:endpoint_certificate, changeset}}
    end
  end

  defp reissue_endpoint(configured, rendered) do
    case PKI.reissue_endpoint_certificate(configured) do
      {:ok, _certificate} ->
        Logger.info("ctrld: re-issued the channel endpoint certificate for #{rendered}")
        {:ok, :endpoint_certificate}

      {:error, {:certificate_too_long, _, _, _} = reason} ->
        {:error, {:endpoint_certificate, PKI.Certificate.describe(reason)}}

      {:error, reason} ->
        {:error, {:endpoint_certificate, reason}}
    end
  end

  defp settings, do: Application.get_env(:ctrld, __MODULE__, [])
end
