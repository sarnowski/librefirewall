defmodule Ctrld.ChannelEndpoint do
  @moduledoc """
  The address an appliance dials, and the one parser for it.

  It is an address literal and never a name. There is no resolver between an
  appliance and its management server, so there is nothing between them to
  poison — and it travels as its own package member rather than as an element
  of the configuration document, which is what makes an endpoint change
  inexpressible over the channel later.

  The rendering is the one the package member carries: a dotted-quad IPv4
  address, a colon, and a decimal port from 1 to 65535.
  """

  @enforce_keys [:address, :port]
  defstruct [:address, :port]

  @type t :: %__MODULE__{address: :inet.ip4_address(), port: 1..65_535}

  @type reason :: :absent | :malformed | {:port_out_of_range, integer()} | :not_ipv4

  @doc "Parse `<ipv4>:<port>`."
  @spec parse(String.t() | nil) :: {:ok, t()} | {:error, reason()}
  def parse(nil), do: {:error, :absent}

  def parse(value) when is_binary(value) do
    case String.trim(value) do
      "" ->
        {:error, :absent}

      trimmed ->
        case String.split(trimmed, ":") do
          [address, port] -> parse_parts(address, port)
          _other -> {:error, :malformed}
        end
    end
  end

  defp parse_parts(address, port) do
    with {:ok, port} <- parse_port(port),
         {:ok, address} <- parse_address(address) do
      {:ok, %__MODULE__{address: address, port: port}}
    end
  end

  defp parse_port(text) do
    case Integer.parse(text) do
      {port, ""} when port in 1..65_535 -> {:ok, port}
      {port, ""} -> {:error, {:port_out_of_range, port}}
      _other -> {:error, :malformed}
    end
  end

  defp parse_address(text) do
    case :inet.parse_ipv4strict_address(String.to_charlist(text)) do
      {:ok, address} -> {:ok, address}
      {:error, :einval} -> {:error, :not_ipv4}
    end
  end

  @doc "The endpoint as the package member renders it."
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{address: address, port: port}) do
    "#{address_text(address)}:#{port}"
  end

  @doc "Just the address, as the channel certificate's subject renders it."
  @spec address_text(:inet.ip4_address()) :: String.t()
  def address_text({a, b, c, d}), do: "#{a}.#{b}.#{c}.#{d}"

  @doc """
  The endpoint this deployment was configured with.

  Raises: the server has nothing to tell an appliance to dial without it, so a
  deployment that did not set it refuses to start rather than issuing packages
  pointing nowhere.
  """
  @spec configured!() :: t()
  def configured! do
    configured = Application.get_env(:ctrld, __MODULE__, [])[:endpoint]

    case parse(configured) do
      {:ok, endpoint} -> endpoint
      {:error, reason} -> raise ArgumentError, "CTRLD_CHANNEL_ENDPOINT " <> explain(reason)
    end
  end

  defp explain(:absent),
    do: "is not set. It must be the address literal and port appliances dial, as <ipv4>:<port>."

  defp explain(:malformed), do: "is not of the form <ipv4>:<port>."
  defp explain(:not_ipv4), do: "does not begin with a dotted-quad IPv4 address literal."

  defp explain({:port_out_of_range, port}),
    do: "names port #{port}; a port is between 1 and 65535."
end
