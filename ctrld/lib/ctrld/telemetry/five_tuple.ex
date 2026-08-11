defmodule Ctrld.Telemetry.FiveTuple do
  @moduledoc """
  The addresses and ports of a recorded frame, read out of its own headers.

  A record's annotation carries what the appliance decided; it does not carry
  *whom about*. The five columns that say that — the protocol, the two
  addresses and the two ports — live nowhere but in the bytes of the frame the
  appliance observed, so reading them is packet dissection and this module is
  the whole of it: Ethernet II, IPv4, and the port pair that opens a TCP or UDP
  header.

  ## Adversary

  **Untrusted network traffic**, at one remove. These bytes are not the
  appliance's: they are what some host on a customer's hostile network put on a
  wire, copied verbatim into a recording and shipped here. Nothing about them
  is a promise. So every field is read by matching a binary of a known size —
  a frame that runs out mid-header is a refusal, never an exception — the work
  is a fixed number of steps with no loop and no recursion in it at all, and no
  byte becomes an atom or reaches a log line.

  ## Why so little is read

  Only what the five columns need. The IPv4 total length, the checksum, the
  identification and the options themselves are all skipped rather than
  validated, because a rule this module does not rely on is a rule it cannot
  get wrong. The header length *is* read, because the ports sit behind it.

  The captured bytes are also not the whole frame where the sink's snap length
  cut it short, which is why nothing here is judged against the datagram's
  stated length: what bounds every read is the bytes actually in hand.

  ## Ports are absent more often than they are unreadable

  A protocol that has no port pair — ICMP, or anything else the appliance
  forwarded — is not a refusal. Its `t:t/0` carries the real protocol and the
  real addresses with both ports zero, because there are no ports to carry and
  zero is what the column holds for one that does not exist. That is a
  different answer from `absent/0`, which is what a frame this module could not
  read at all is worth, and the two are told apart by the protocol: `absent/0`
  is the only value that carries protocol zero.
  """

  @ethernet_header 14
  @ipv4_ethertype 0x0800
  @ipv4_minimum_header 20
  @ipv4 4

  @tcp 6
  @udp 17

  # The one value that is not a protocol. IANA assigns 0 to IPv6's hop-by-hop
  # options header, which cannot be an IPv4 next-protocol, so no frame this
  # module reads successfully can carry it — which is what lets it stand for
  # "not read" in a column that has no room to say so.
  @unread_protocol 0

  @enforce_keys [
    :protocol,
    :source_address,
    :destination_address,
    :source_port,
    :destination_port
  ]

  defstruct [
    :protocol,
    :source_address,
    :destination_address,
    :source_port,
    :destination_port
  ]

  @type address :: {0..255, 0..255, 0..255, 0..255}

  @type t :: %__MODULE__{
          protocol: 0..255,
          source_address: address(),
          destination_address: address(),
          source_port: 0..65_535,
          destination_port: 0..65_535
        }

  @typedoc """
  Why a frame's five-tuple could not be read.

  One value per rule broken, because these are counted per appliance and a
  reason standing for several would leave an operator unable to tell a link
  carrying something other than IPv4 from one carrying IPv4 that is malformed.
  """
  @type refusal ::
          :no_frame
          | {:shorter_than_ethernet, non_neg_integer()}
          | {:not_ipv4_ethertype, 0..65_535}
          | {:shorter_than_ipv4, non_neg_integer()}
          | {:not_ipv4, 0..15}
          | {:header_below_minimum, pos_integer()}
          | {:header_exceeds_frame, pos_integer(), non_neg_integer()}
          | {:later_fragment, pos_integer()}
          | {:shorter_than_ports, 0..255, non_neg_integer()}

  @doc "The protocol number no frame read here can carry, and `absent/0` does."
  @spec unread_protocol() :: 0
  def unread_protocol, do: @unread_protocol

  @doc """
  What a row carries where the frame could not be read.

  Zero in all five columns, and the protocol is what makes it unmistakable: a
  frame that *was* read always carries a real IPv4 next-protocol, which is
  never zero, so `protocol = 0` is exactly the set of rows whose frame this
  module refused. The refusal itself is counted where it happened; the row says
  only that there was nothing to say.
  """
  @spec absent() :: t()
  def absent do
    %__MODULE__{
      protocol: @unread_protocol,
      source_address: {0, 0, 0, 0},
      destination_address: {0, 0, 0, 0},
      source_port: 0,
      destination_port: 0
    }
  end

  @doc """
  Read the five-tuple of one recorded frame.

  `frame` is the captured bytes exactly as the record carried them, starting at
  the Ethernet destination address.
  """
  @spec read(binary()) :: {:ok, t()} | {:error, refusal()}
  def read(<<>>), do: {:error, :no_frame}

  def read(frame) when is_binary(frame) and byte_size(frame) < @ethernet_header,
    do: {:error, {:shorter_than_ethernet, byte_size(frame)}}

  def read(
        <<_destination::binary-size(6), _source::binary-size(6), ethertype::unsigned-big-16,
          payload::binary>>
      ) do
    case ethertype do
      @ipv4_ethertype -> ipv4(payload)
      other -> {:error, {:not_ipv4_ethertype, other}}
    end
  end

  @doc "A refusal in the words an operator reading it needs."
  @spec describe(refusal()) :: String.t()
  def describe(:no_frame),
    do: "a record carries no frame at all, so it has no addresses or ports"

  def describe({:shorter_than_ethernet, size}),
    do: "a #{size}-byte frame is below the #{@ethernet_header} an Ethernet II header needs"

  def describe({:not_ipv4_ethertype, ethertype}),
    do: "a frame carries EtherType #{hex(ethertype)}, and this reader has only IPv4"

  def describe({:shorter_than_ipv4, size}),
    do: "#{size} bytes follow an Ethernet header, below the #{@ipv4_minimum_header} IPv4 needs"

  def describe({:not_ipv4, version}),
    do: "a frame declaring IPv4 opens on IP version #{version}"

  def describe({:header_below_minimum, header}),
    do: "an IPv4 header states #{header} bytes, below the #{@ipv4_minimum_header} it has to be"

  def describe({:header_exceeds_frame, header, available}),
    do: "an IPv4 header states #{header} bytes with #{available} captured"

  def describe({:later_fragment, offset}),
    do: "a fragment at offset #{offset} carries no port pair, those being in the first"

  def describe({:shorter_than_ports, protocol, available}),
    do: "#{available} bytes follow an IPv4 header, below the 4 protocol #{protocol}'s ports need"

  @spec ipv4(binary()) :: {:ok, t()} | {:error, refusal()}
  defp ipv4(payload) when byte_size(payload) < @ipv4_minimum_header,
    do: {:error, {:shorter_than_ipv4, byte_size(payload)}}

  defp ipv4(
         <<version::4, header_words::4, _service::8, _total::unsigned-big-16,
           _identification::unsigned-big-16, _flags::3, fragment_offset::13, _ttl::8, protocol::8,
           _checksum::unsigned-big-16, source::binary-4, destination::binary-4, _rest::binary>> =
           payload
       ) do
    header = header_words * 4

    cond do
      version != @ipv4 ->
        {:error, {:not_ipv4, version}}

      header < @ipv4_minimum_header ->
        {:error, {:header_below_minimum, header}}

      byte_size(payload) < header ->
        {:error, {:header_exceeds_frame, header, byte_size(payload)}}

      # Only the first fragment of a datagram carries the transport header, so a
      # later one has no ports to read rather than unreadable ones. The more-
      # fragments flag is deliberately not consulted: a first fragment is at
      # offset zero and carries its ports whether more follow or not.
      fragment_offset > 0 ->
        {:error, {:later_fragment, fragment_offset}}

      true ->
        after_header = binary_part(payload, header, byte_size(payload) - header)
        ports(after_header, protocol, source, destination)
    end
  end

  @spec ports(binary(), 0..255, binary(), binary()) :: {:ok, t()} | {:error, refusal()}
  defp ports(after_header, protocol, source, destination) when protocol in [@tcp, @udp] do
    case after_header do
      <<source_port::unsigned-big-16, destination_port::unsigned-big-16, _::binary>> ->
        {:ok, tuple(protocol, source, destination, source_port, destination_port)}

      shorter ->
        {:error, {:shorter_than_ports, protocol, byte_size(shorter)}}
    end
  end

  defp ports(_after_header, protocol, source, destination),
    do: {:ok, tuple(protocol, source, destination, 0, 0)}

  @spec tuple(0..255, binary(), binary(), 0..65_535, 0..65_535) :: t()
  defp tuple(protocol, source, destination, source_port, destination_port) do
    %__MODULE__{
      protocol: protocol,
      source_address: address(source),
      destination_address: address(destination),
      source_port: source_port,
      destination_port: destination_port
    }
  end

  @spec address(binary()) :: address()
  defp address(<<a, b, c, d>>), do: {a, b, c, d}

  @spec hex(0..65_535) :: String.t()
  defp hex(value) do
    "0x" <> (value |> Integer.to_string(16) |> String.downcase() |> String.pad_leading(4, "0"))
  end
end
