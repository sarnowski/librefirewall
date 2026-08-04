defmodule Ctrld.Telemetry.Store do
  @moduledoc """
  The telemetry store: ClickHouse over its HTTP interface.

  The client is `Req` against ClickHouse's own HTTP endpoint rather than a
  database driver, and that is the whole dependency: the HTTP interface takes
  a statement and a body and answers with rows, which is everything this
  server asks of it, and `Req` is already here. A native-protocol driver would
  be a second connection pool and a second thing to pin for no capability this
  server needs.

  Rows go in as `JSONEachRow` and come back the same way, so a row is a map
  with the column names on it in both directions and there is no positional
  encoding to keep in step with the schema.

  Nothing here retries. A failure to reach the store is returned as an error
  with what the store said, because a telemetry write that silently vanished
  is a gap in the record that nothing will ever notice.
  """

  alias Ctrld.Telemetry.Schema

  @receive_timeout 15_000

  @type reason :: {:http, pos_integer(), String.t()} | {:transport, term()} | :not_configured

  @doc "Apply the schema. Idempotent, because every statement is `IF NOT EXISTS`."
  @spec migrate() :: :ok | {:error, reason()}
  def migrate do
    Enum.reduce_while(Schema.statements(), :ok, fn statement, :ok ->
      case execute(statement) do
        {:ok, _body} -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  @doc "Whether the store answers at all — the readiness the gate insists on."
  @spec ready?() :: boolean()
  def ready? do
    match?({:ok, _}, execute("SELECT 1"))
  end

  @doc "Run a statement that returns nothing worth parsing."
  @spec execute(String.t()) :: {:ok, String.t()} | {:error, reason()}
  def execute(statement) when is_binary(statement), do: post(statement, nil)

  @doc """
  Insert rows into one of the schema's tables.

  The table name is checked against the schema's own list rather than
  interpolated as given: it is the one part of the statement that is not a
  literal here, and a name from the schema cannot be a statement.
  """
  @spec insert(String.t(), [map()]) :: :ok | {:error, reason() | {:unknown_table, String.t()}}
  def insert(_table, []), do: :ok

  def insert(table, rows) when is_binary(table) and is_list(rows) do
    if table in Schema.tables() do
      body = Enum.map_join(rows, "\n", &Jason.encode!/1)

      case post("INSERT INTO #{table} FORMAT JSONEachRow", body) do
        {:ok, _} -> :ok
        {:error, reason} -> {:error, reason}
      end
    else
      {:error, {:unknown_table, table}}
    end
  end

  @doc "Run a query and return its rows as maps."
  @spec query(String.t()) :: {:ok, [map()]} | {:error, reason()}
  def query(statement) when is_binary(statement) do
    case post(statement <> " FORMAT JSONEachRow", nil) do
      {:ok, body} -> {:ok, decode_rows(body)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc "A refusal in the words an operator reading it needs."
  @spec describe(reason() | {:unknown_table, String.t()}) :: String.t()
  def describe(:not_configured), do: "CLICKHOUSE_URL is not set"
  def describe({:http, status, body}), do: "the store answered #{status}: #{String.trim(body)}"
  def describe({:transport, reason}), do: "the store could not be reached: #{inspect(reason)}"
  def describe({:unknown_table, table}), do: "#{table} is not a table of this schema"

  defp decode_rows(body) do
    body
    |> String.split("\n", trim: true)
    |> Enum.map(&Jason.decode!/1)
  end

  defp post(statement, body) do
    case configuration() do
      {:ok, settings} -> request(settings, statement, body)
      :error -> {:error, :not_configured}
    end
  end

  defp request(settings, statement, body) do
    result =
      Req.post(
        url: settings.url,
        params: [database: settings.database, query: statement],
        headers: [
          {"x-clickhouse-user", settings.username},
          {"x-clickhouse-key", settings.password}
        ],
        body: body || "",
        receive_timeout: @receive_timeout,
        retry: false,
        decode_body: false
      )

    case result do
      {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
        {:ok, to_string(body)}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, {:http, status, to_string(body)}}

      {:error, reason} ->
        {:error, {:transport, reason}}
    end
  end

  defp configuration do
    settings = Application.get_env(:ctrld, __MODULE__, [])

    case settings[:url] do
      url when is_binary(url) and url != "" ->
        {:ok,
         %{
           url: url,
           database: settings[:database] || "default",
           username: settings[:username] || "default",
           password: settings[:password] || ""
         }}

      _absent ->
        :error
    end
  end
end
