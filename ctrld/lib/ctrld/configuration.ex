defmodule Ctrld.Configuration do
  @moduledoc """
  The configuration document a package carries, and what this server checks
  about it.

  **The appliance is the authority on whether a document is acceptable.** It
  holds a closed schema and a validating protection domain that re-decides
  every rule, and a second copy of that grammar here would be a second
  implementation of one contract, diverging silently and refusing documents
  the appliance would have taken. So this module deliberately checks only what
  it can check without owning the grammar: the size the package bounds the
  member at, that the bytes are well-formed XML, that the root is a
  configuration document, and that the four sections the appliance requires
  are each present once. Everything past that — addresses, rules, the
  relationships between them — the appliance decides, and the interface says
  so rather than implying this server has already approved it.

  Document type declarations and entity declarations are refused before the
  parser runs. The appliance's own reader admits neither, so refusing them is
  faithful to the target rather than a workaround — and it keeps an entity
  expansion out of a parser that would otherwise be reachable from an upload.
  """

  @maximum_bytes 64 * 1024
  @required_sections ~w(interfaces neighbours rules management)

  @type reason ::
          {:too_large, pos_integer()}
          | :declares_entities
          | :not_well_formed
          | {:wrong_root, String.t()}
          | {:missing_section, String.t()}
          | {:repeated_section, String.t()}

  @doc "The size bound the package member imposes, in bytes."
  @spec maximum_bytes() :: pos_integer()
  def maximum_bytes, do: @maximum_bytes

  @doc "The sections the appliance's schema requires, each exactly once."
  @spec required_sections() :: [String.t()]
  def required_sections, do: @required_sections

  @doc "Check a document as far as this server is entitled to."
  @spec validate(binary()) :: :ok | {:error, reason()}
  def validate(document) when is_binary(document) do
    with :ok <- check_size(document),
         :ok <- check_no_entities(document),
         {:ok, root} <- scan(document) do
      check_sections(root)
    end
  end

  @doc "A refusal in the words the administrator editing the document needs."
  @spec describe(reason()) :: String.t()
  def describe({:too_large, size}),
    do: "the document is #{size} bytes and the package bounds it at #{@maximum_bytes}"

  def describe(:declares_entities),
    do:
      "the document declares a document type or an entity; the appliance's reader admits neither"

  def describe(:not_well_formed), do: "the document is not well-formed XML"

  def describe({:wrong_root, name}),
    do: "the root element is <#{name}>; it must be <configuration>"

  def describe({:missing_section, name}), do: "the document has no <#{name}> section"

  def describe({:repeated_section, name}),
    do: "the document has more than one <#{name}> section"

  defp check_size(document) do
    if byte_size(document) > @maximum_bytes,
      do: {:error, {:too_large, byte_size(document)}},
      else: :ok
  end

  defp check_no_entities(document) do
    lowered = String.downcase(document)

    if String.contains?(lowered, "<!doctype") or String.contains?(lowered, "<!entity") do
      {:error, :declares_entities}
    else
      :ok
    end
  end

  # The scanner is handed the document's *bytes*, one per list element, and not
  # its codepoints. It decodes the encoding the declaration names for itself, so
  # a codepoint list would present it an already-decoded character where it
  # expects a UTF-8 byte and it would refuse the character as illegal — which
  # made every document carrying so much as a dash outside ASCII unonboardable,
  # while the appliance that has to accept it reads bytes and took it happily.
  defp scan(document) do
    {root, _rest} = :xmerl_scan.string(:erlang.binary_to_list(document), quiet: true)
    {:ok, root}
  rescue
    _ -> {:error, :not_well_formed}
  catch
    _, _ -> {:error, :not_well_formed}
  end

  defp check_sections(
         {:xmlElement, name, _expanded, _ns, _namespace, _parents, _pos, _attrs, children,
          _language, _xmlbase, _elementdef}
       ) do
    case Atom.to_string(name) do
      "configuration" -> check_required(children)
      other -> {:error, {:wrong_root, other}}
    end
  end

  defp check_sections(_other), do: {:error, :not_well_formed}

  defp check_required(children) do
    present =
      children
      |> Enum.flat_map(fn
        {:xmlElement, name, _e, _ns, _n, _p, _pos, _a, _c, _l, _x, _d} -> [Atom.to_string(name)]
        _other -> []
      end)
      |> Enum.frequencies()

    Enum.reduce_while(@required_sections, :ok, fn section, :ok ->
      case Map.get(present, section, 0) do
        0 -> {:halt, {:error, {:missing_section, section}}}
        1 -> {:cont, :ok}
        _many -> {:halt, {:error, {:repeated_section, section}}}
      end
    end)
  end

  @doc """
  The document a new appliance is offered as a starting point.

  It is a starting point and not a default: it names one dataplane pair, one
  neighbour on each, a management address, and an empty rule set — and an
  empty rule set forwards nothing, because the appliance is default-deny. An
  administrator who ships this unedited gets an appliance that comes up, says
  so, and passes no traffic, which is the right thing for a document nobody
  has thought about yet.
  """
  @spec template() :: String.t()
  def template do
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <configuration>
        <interfaces>
            <interface id="dataplane-0" port="0" enabled="true"
                       mac="52:54:00:12:34:50" address="10.0.0.1" prefix-length="24"/>
            <interface id="dataplane-1" port="1" enabled="true"
                       mac="52:54:00:12:34:51" address="10.0.1.1" prefix-length="24"/>
        </interfaces>
        <neighbours>
            <neighbour id="endpoint-a" interface="dataplane-0"
                       address="10.0.0.2" mac="52:54:00:00:00:0a"/>
            <neighbour id="endpoint-b" interface="dataplane-1"
                       address="10.0.1.2" mac="52:54:00:00:00:0b"/>
        </neighbours>
        <rules/>
        <management mac="52:54:00:12:34:52" address="10.0.2.15"
                    prefix-length="24" enabled="true" gateway="10.0.2.2"/>
    </configuration>
    """
  end
end
