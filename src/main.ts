export { };

const classToName: {
  [k: number]: string | undefined,
} = {
  1: "IN",
  3: "CH",
  4: "HS",
  254: "NONE",
  255: "ANY",
};

const typeToName: {
  [k: number]: string | undefined,
} = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  28: "AAAA",
  41: "OPT",
};

function classAsStr(num: number): string {
  const name = classToName[num];
  return `${num} ${name ? `(${name})` : ""}`;
}

function typeAsStr(num: number): string {
  const name = typeToName[num];
  return `${num} ${name ? `(${name})` : ""}`;
}

type Node = {
  Name: string;
  Value?: string,
  Invalid?: boolean,

  Length: number,

  bitField?: boolean,
  InsideNodes?: Node[],
};

class Header {
  ID: number;
  Flags: {
    Query: boolean;
    OpCode: number,
    BitAA: boolean,
    BitTC: boolean,
    BitRD: boolean,
    BitRA: boolean,
    BitReserved: boolean,
    BitAD: boolean,
    BitCD: boolean,
    RCode: number,
  };
  QDCount: number;
  ANCount: number;
  NSCount: number;
  ARCount: number;

  constructor(msg: Uint8Array) {
    const m = new DataView(msg.buffer);
    this.ID = m.getUint16(0);
    const flags = m.getUint16(2);
    this.Flags = {
      Query: (flags & 1 << 15) === 0,
      OpCode: (flags >> 11) & 0b1111,
      BitAA: (flags & 1 << 10) !== 0,
      BitTC: (flags & 1 << 9) !== 0,
      BitRD: (flags & 1 << 8) !== 0,
      BitRA: (flags & 1 << 7) !== 0,
      BitReserved: (flags & 1 << 6) !== 0,
      BitAD: (flags & 1 << 5) !== 0,
      BitCD: (flags & 1 << 4) !== 0,
      RCode: (flags & 0b1111),
    };

    this.QDCount = m.getUint16(4);
    this.ANCount = m.getUint16(6);
    this.NSCount = m.getUint16(8);
    this.ARCount = m.getUint16(10);
  }

  asNode(): Node {
    return {
      Name: "Header",
      Length: 12,
      InsideNodes: [
        { Name: "ID", Value: this.ID.toString(), Length: 2, },
        {
          Name: "Bitfield",
          Length: 2,
          bitField: true,
          InsideNodes: [
            { Name: "QR", Value: this.Flags.Query ? "query" : "response", Length: 1 },
            { Name: "OpCode", Value: this.Flags.OpCode.toString(), Length: 4 },
            { Name: "Bit AA", Value: this.Flags.BitAA.toString(), Length: 1 },
            { Name: "Bit TC", Value: this.Flags.BitTC.toString(), Length: 1 },
            { Name: "Bit RD", Value: this.Flags.BitRD.toString(), Length: 1 },
            { Name: "Bit RA", Value: this.Flags.BitRA.toString(), Length: 1 },
            { Name: "Reserved Bit", Value: this.Flags.BitReserved.toString(), Length: 1 },
            { Name: "Bit AD", Value: this.Flags.BitAD.toString(), Length: 1 },
            { Name: "Bit CD", Value: this.Flags.BitCD.toString(), Length: 1 },
            { Name: "RCode", Value: this.Flags.RCode.toString(), Length: 4 },
          ]
        },
        { Name: "Questions Count", Value: this.QDCount.toString(), Length: 2, },
        { Name: "Answers Count", Value: this.ANCount.toString(), Length: 2, },
        { Name: "Authorities Count", Value: this.NSCount.toString(), Length: 2, },
        { Name: "Additionals Count", Value: this.ARCount.toString(), Length: 2, },

      ],
    };
  }
}

class Name {
  nameLengthNoFollowPtr: number;
  name: string;

  labelsUpToFirstPtr: {
    root: boolean;
    str: string;
    length: number;
  }[];
  firstPtr?: number;

  constructor(msg: Uint8Array, offset: number) {
    const startOffset = offset;
    let nameEndOffset = 0;

    const raw = new Uint8Array(255);
    let length = 0;

    const seenPtrs = new Set();

    while (true) {
      if (offset >= msg.length) {
        throw new Error("invalid DNS name encoding");
      }

      if ((msg[offset] & 0xC0) == 0xC0) {
        if (msg.length == offset + 1) {
          throw new Error("invalid DNS name encoding, invalid pointer (one byte)");
        }
        if (nameEndOffset == 0) {
          nameEndOffset = offset + 1;
        }
        offset = ((msg[offset] ^ 0xC0) << 8) | msg[offset + 1];
        if (seenPtrs.has(seenPtrs)) {
          throw new Error("invalid DNS name encoding, pointer loop");
        }
        seenPtrs.add(offset);
        continue;
      }

      const labelLength = msg[offset];

      if (labelLength == 0) {
        if (length + 1 > 255) {
          throw new Error("invalid DNS name encoding, name too long (> 255 Bytes)");
        }

        raw[length] = 0;
        length++;

        if (nameEndOffset == 0) {
          nameEndOffset = offset;
        }

        this.nameLengthNoFollowPtr = (nameEndOffset - startOffset) + 1;

        let strName = "";
        this.labelsUpToFirstPtr = [];

        const rawName = raw.slice(0, length);
        for (let i = 0; rawName[i] != 0; i += rawName[i] + 1) {
          let labelStr = "";
          const label = rawName.slice(i + 1, i + 1 + rawName[i]);
          for (let j = 0; j < label.length; j++) {
            if (label[j] === '.'.charCodeAt(0)) {
              labelStr += "\\.";
            } else if (label[j] === '\\'.charCodeAt(0)) {
              labelStr += "\\\\";
            } else if (label[j] < '!'.charCodeAt(0) || label[j] > '~'.charCodeAt(0)) {
              labelStr += "\\" + ("000" + label[j]).slice(-3);
            } else {
              labelStr += String.fromCharCode(label[j]);
            }
          }

          strName += labelStr + ".";
          if (i < this.nameLengthNoFollowPtr - 2) {
            this.labelsUpToFirstPtr.push({ str: labelStr, length: label.length + 1, root: false });
          }
        }

        if (seenPtrs.size == 0) {
          this.labelsUpToFirstPtr.push({ str: ".", length: 1, root: true });
        }

        if (strName == "") {
          strName = ".";
        }

        if (seenPtrs.size > 0) {
          this.firstPtr = ((msg[nameEndOffset - 1] ^ 0xC0) << 8) | msg[nameEndOffset];
        }
        this.name = strName;
        return;
      }

      if (labelLength > 63) {
        throw new Error("invalid DNS name encoding, name is using reserved label bits (label longer than 63 characters)");
      }

      if (offset + labelLength + 1 >= msg.length) {
        throw new Error("invalid DNS name encoding");
      }

      const label = msg.slice(offset, offset + labelLength + 1);
      if (length + label.length > 255) {
        throw new Error("invalid DNS name encoding, name too long (> 255 Bytes)");
      }

      offset += labelLength + 1;
      raw.set(label, length);
      length += label.length;
    }
  }

  asNode(name: string): Node {
    const insideNodes: Node[] = [];

    for (const label of this.labelsUpToFirstPtr) {
      if (label.root) {
        insideNodes.push({
          Name: "Root label",
          Value: label.str,
          Length: label.length,
        });
        continue;
      }
      insideNodes.push({
        Name: "Label",
        Value: label.str,
        Length: label.length,
      });
    }

    if (this.firstPtr) {
      insideNodes.push({
        Name: "Compression pointer",
        Value: this.firstPtr.toString(),
        Length: 2,
      });
    }

    return {
      Name: name,
      Value: this.name,
      Length: this.nameLengthNoFollowPtr,
      InsideNodes: insideNodes,
    };
  }
}

class Queston {
  name: Name;
  type: number;
  class: number;
  questionLength: number;
  node: Node;

  constructor(msg: Uint8Array, offset: number) {
    try {
      this.name = new Name(msg, offset);
    } catch (err) {
      if (err instanceof Error) {
        throw new Error(`invalid question, ${err.message}`);
      }
      throw new Error("internal error");
    }

    offset += this.name.nameLengthNoFollowPtr;

    const m = new DataView(msg.buffer.slice(offset));
    if (m.buffer.byteLength < 4) {
      throw new Error("invalid question");
    }
    this.type = m.getUint16(0);
    this.class = m.getUint16(2);

    this.questionLength = this.name.nameLengthNoFollowPtr + 4;
    this.node = {
      Name: "Question",
      Length: this.name.nameLengthNoFollowPtr + 4,
      InsideNodes: [
        this.name.asNode("Name"),
        { Name: "Type", Value: typeAsStr(this.type), Length: 2 },
        { Name: "Class", Value: classAsStr(this.class), Length: 2 },
      ]
    };
  }
}

class Resource {
  name: Name;
  type: number;
  class: number;
  ttl: number;
  length: number;

  resourceLength: number;
  node: Node;

  constructor(msg: Uint8Array, offset: number, section: "Answers" | "Authorities" | "Additionals", hdr: Header) {
    try {
      this.name = new Name(msg, offset);
    } catch (err) {
      if (err instanceof Error) {
        throw new Error(`invalid resource header, ${err.message}`);
      }
      throw new Error("internal error");
    }

    this.resourceLength = this.name.nameLengthNoFollowPtr;
    offset += this.name.nameLengthNoFollowPtr;

    const m = new DataView(msg.buffer);
    if (m.buffer.byteLength < offset + 10) {
      throw new Error("invalid resource header");
    }

    this.type = m.getUint16(offset);
    this.class = m.getUint16(offset + 2);
    this.ttl = m.getUint32(offset + 4);
    this.length = m.getUint16(offset + 8);

    this.resourceLength += this.length + 10;
    if (offset + 10 + this.length > msg.length) {
      throw new Error("invalid resource header");
    }

    const rd: Node = {
      Name: "Resource Data",
      Length: this.length,
    };

    try {
      const n = this.parseResourceData(msg, this.type, offset + 10, this.length);
      if (n) {
        rd.InsideNodes = [n];
      }
    } catch (err) {
      if (err instanceof Error) {
        rd.InsideNodes = [{
          Name: "Invalid resource data",
          Value: err.message,
          Length: this.length,
          Invalid: true,
        }];
      } else {
        throw new Error("internal error");
      }
    }

    if (this.type == 41) {
      const nameNode = this.name.asNode("Name");
      if (this.name.name !== ".") {
        nameNode.Invalid = true;
        nameNode.Value = `invalid name: "${nameNode.Value}", expected root name, because this is an EDNS(0) header`;
      }
      this.node = {
        Name: "Resource",
        Length: this.resourceLength,
        Invalid: section !== "Additionals",
        Value: section !== "Additionals" ? `unexpected OPT EDNS(0) in ${section} section` : undefined,
        InsideNodes: [
          nameNode,
          { Name: "Type", Value: typeAsStr(this.type), Length: 2 },
          {
            Name: "Class",
            Value: typeAsStr(this.class),
            Length: 2,
            InsideNodes: [{
              Name: "Payload",
              Value: this.class.toString(),
              Length: 2
            }],
          },
          {
            Name: "TTL",
            Value: this.ttl.toString(),
            Length: 4,
            InsideNodes: [
              {
                Name: "Partial extended RCode",
                Value: `${(this.ttl >> 24).toString()}, Extended RCode: ${((this.ttl >> 24) << 4) | hdr.Flags.RCode}`,
                Length: 1,
              },
              {
                Name: "Version",
                Value: (this.ttl >> 16).toString(),
                Length: 1,
              },
              {
                Name: "Extended flags",
                Length: 2,
                bitField: true,
                InsideNodes: [
                  {
                    Name: "Bit DO",
                    Value: ((this.ttl & (1 << 15)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 14",
                    Value: ((this.ttl & (1 << 14)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 13",
                    Value: ((this.ttl & (1 << 13)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 12",
                    Value: ((this.ttl & (1 << 12)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 11",
                    Value: ((this.ttl & (1 << 11)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 10",
                    Value: ((this.ttl & (1 << 10)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 9",
                    Value: ((this.ttl & (1 << 9)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 8",
                    Value: ((this.ttl & (1 << 8)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 7",
                    Value: ((this.ttl & (1 << 7)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 6",
                    Value: ((this.ttl & (1 << 6)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 5",
                    Value: ((this.ttl & (1 << 5)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 4",
                    Value: ((this.ttl & (1 << 4)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 3",
                    Value: ((this.ttl & (1 << 3)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 2",
                    Value: ((this.ttl & (1 << 2)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 1",
                    Value: ((this.ttl & (1 << 1)) !== 0).toString(),
                    Length: 1,
                  },
                  {
                    Name: "Reserved bit 0",
                    Value: ((this.ttl & 1) !== 0).toString(),
                    Length: 1,
                  },
                ],
              },
            ],
          },
          { Name: "Length", Value: this.length.toString(), Length: 2 },
          rd,
        ]
      };
    } else {
      this.node = {
        Name: "Resource",
        Length: this.resourceLength,
        InsideNodes: [
          this.name.asNode("Name"),
          { Name: "Type", Value: typeAsStr(this.type), Length: 2 },
          { Name: "Class", Value: classAsStr(this.class), Length: 2 },
          { Name: "TTL", Value: this.ttl.toString(), Length: 4 },
          { Name: "Length", Value: this.length.toString(), Length: 2 },
          rd,
        ]
      };
    }
  }

  private parseResourceData(msg: Uint8Array, type: number, offset: number, length: number): Node | null {
    switch (type) {
      case 1: {
        if (length != 4) {
          throw new Error("invalid A resource, expected 4 Byte resource length");
        }
        return {
          Name: "Resource A",
          Length: length,
          InsideNodes: [{
            Name: "Address",
            Value: msg.slice(offset, offset + length).join("."),
            Length: length,
          }],
        };
      }
      case 2: {
        const name = new Name(msg, offset);
        if (name.nameLengthNoFollowPtr != length) {
          throw new Error("invalid NS resource, name is longer than the resource length");
        }
        return {
          Name: "Resource NS",
          Length: length,
          InsideNodes: [name.asNode("NS")],
        };
      }
      case 5: {
        const name = new Name(msg, offset);
        if (name.nameLengthNoFollowPtr != length) {
          throw new Error("invalid CNAME resource, name is longer than the resource length");
        }
        return {
          Name: "Resource CNAME",
          Length: length,
          InsideNodes: [name.asNode("CNAME")],
        };
      }
      case 6: {
        const ns = new Name(msg, offset);
        const mbox = new Name(msg, offset + ns.nameLengthNoFollowPtr);
        if (mbox.nameLengthNoFollowPtr + ns.nameLengthNoFollowPtr + 20 > length) {
          throw new Error("invalid SOA resource, resource length is too low");
        }

        const view = new DataView(msg.buffer, offset, 20);
        return {
          Name: "Resource SOA",
          Length: length,
          InsideNodes: [
            ns.asNode("NS"),
            mbox.asNode("MBox"),
            { Name: "Serial", Value: view.getUint32(0).toString(), Length: 4 },
            { Name: "Refresh", Value: view.getUint32(4).toString(), Length: 4 },
            { Name: "Retry", Value: view.getUint32(8).toString(), Length: 4 },
            { Name: "Expire", Value: view.getUint32(12).toString(), Length: 4 },
            { Name: "Minimum", Value: view.getUint32(16).toString(), Length: 4 },
          ],
        };
      }
      case 12: {
        const name = new Name(msg, offset);
        if (name.nameLengthNoFollowPtr != length) {
          throw new Error("invalid PTR resource, name is longer than the resource length");
        }
        return {
          Name: "Resource PTR",
          Length: length,
          InsideNodes: [name.asNode("PTR")],
        };
      }
      case 15: {
        if (length < 2) {
          throw new Error("invalid MX resource, missing preference and name");
        }
        const name = new Name(msg, offset + 2);
        if (name.nameLengthNoFollowPtr > length - 2) {
          throw new Error("invalid MX resource, resource is longer than the resource length");
        }
        if (name.nameLengthNoFollowPtr < length - 2) {
          throw new Error("invalid MX resource, resource is shorter than the resource length");
        }
        return {
          Name: "Resource MX",
          Length: length,
          InsideNodes: [
            {
              Name: "Preference",
              Value: new DataView(msg.buffer, offset).getUint16(0).toString(),
              Length: 2
            },
            name.asNode("MX")
          ],
        };
      }
      case 28: {
        if (length != 16) {
          throw new Error("invalid AAAA resource, expected 16 Byte resource length");
        }
        const ipv6 = msg.slice(offset, offset + length);
        const hexSegments = [];
        for (let i = 0; i < 16; i += 2) {
          hexSegments.push(((ipv6[i] << 8) + ipv6[i + 1]).toString(16));
        }
        return {
          Name: "Resource AAAA",
          Length: length,
          InsideNodes: [{
            Name: "Address",
            Value: hexSegments.join(":"),
            Length: length,
          }],
        };
      }
      default:
        return null;
    }
  }
}

class Message {
  Buf: Uint8Array;
  Node: Node;

  constructor(msg: Uint8Array) {
    this.Buf = msg;

    const questionsNode: Node = {
      Name: "Questions",
      Length: 0,
      InsideNodes: [],
    };
    const answersNode: Node = {
      Name: "Answers",
      Length: 0,
      InsideNodes: [],
    };
    const authoritiesNode: Node = {
      Name: "Authorities",
      Length: 0,
      InsideNodes: [],
    };
    const additionalsNode: Node = {
      Name: "Additionals",
      Length: 0,
      InsideNodes: [],
    };

    if (msg.length < 12) {
      this.Node = {
        Name: "Message",
        Length: msg.length,
        InsideNodes: [{
          Name: "Invalid message",
          Value: "dns message too short, header not found",
          Length: msg.length,
          Invalid: true,
        }],
      };
      return;
    }

    const header = new Header(msg.slice(0, 12));
    this.Node = {
      Name: "Message",
      Length: msg.length,
      InsideNodes: [
        header.asNode(),
      ],
    };


    let offset = 12;
    let type = "question";
    try {
      this.Node.InsideNodes?.push(questionsNode);
      for (let i = 0; i < header.QDCount; i++) {
        const q = new Queston(msg, offset);
        offset += q.questionLength;
        questionsNode.Length += q.questionLength;
        questionsNode.InsideNodes?.push(q.node);
      }

      type = "answer resource";
      this.Node.InsideNodes?.push(answersNode);
      for (let i = 0; i < header.ANCount; i++) {
        const q = new Resource(msg, offset, "Answers", header);
        offset += q.resourceLength;
        answersNode.Length += q.resourceLength;
        answersNode.InsideNodes?.push(q.node);
      }

      type = "authority resource";
      this.Node.InsideNodes?.push(authoritiesNode);
      for (let i = 0; i < header.NSCount; i++) {
        const q = new Resource(msg, offset, "Authorities", header);
        offset += q.resourceLength;
        authoritiesNode.Length += q.resourceLength;
        authoritiesNode.InsideNodes?.push(q.node);
      }

      type = "additional resource";
      this.Node.InsideNodes?.push(additionalsNode);
      for (let i = 0; i < header.ARCount; i++) {
        const q = new Resource(msg, offset, "Additionals", header);
        offset += q.resourceLength;
        additionalsNode.Length += q.resourceLength;
        additionalsNode.InsideNodes?.push(q.node);
      }
    } catch (err) {
      if (err instanceof Error) {
        const trailing = msg.slice(offset);
        this.Node.InsideNodes?.push({
          Name: trailing.length == 0 ? `invalid header` : `invalid message`,
          Value: trailing.length == 0 ? `missing ${type}, count in header is bigger than the actual count of ${type}s found the message` : err.message,
          Length: trailing.length,
          Invalid: true,
        });
        offset += trailing.length;
      } else {
        throw new Error("internal error");
      }
    }

    const trailing = msg.slice(offset);
    if (trailing.length > 0) {
      this.Node.InsideNodes?.push({
        Name: "Trailing data",
        Length: trailing.length,
        Invalid: true,
      });
    }
  }
}

function scrollIntoViewIfNeeded(target: HTMLElement) {
  if (target.getBoundingClientRect().bottom > window.innerHeight) {
    target.scrollIntoView(false);
  }
  if (target.getBoundingClientRect().top < 0) {
    target.scrollIntoView();
  }
}

function render() {
  const nodeIDPrefix = "node-";
  const binaryViewerIDPrefix = "viewer-";

  let prevID: string | null = null;
  let clickID: string | null = null;

  const main = document.createElement("div");
  main.id = "main";
  main.addEventListener("click", (e) => {
    if (clickID) {
      if (e.target instanceof HTMLElement) {
        if (e.target.classList.contains("node-hide")) {
          e.target.parentElement?.parentElement?.classList.toggle("node-hidden");
        }
        const nodeEl = document.getElementById(nodeIDPrefix + clickID)!;
        if (nodeEl) {
          scrollIntoViewIfNeeded(nodeEl);
        }
        const binaryEl = document.getElementById(binaryViewerIDPrefix + clickID)!;
        if (binaryEl) {
          scrollIntoViewIfNeeded(binaryEl);
        }
      }
    }
  });
  main.addEventListener("mousemove", (e) => {
    let target = e.target;
    if (target instanceof HTMLElement) {
      while (target.id === "") {
        target = target.parentElement;
        if (!(target instanceof HTMLElement)) {
          clickID = null;
          return;
        }
      }

      const details = target.querySelector(".details");
      if (details) {
        if (!(details.contains(e.target as HTMLElement) || details.isSameNode(e.target as HTMLElement))) {
          clickID = null;
          return;
        }
      }

      let id = "";
      if (target.id.startsWith(nodeIDPrefix)) {
        id = target.id.slice(nodeIDPrefix.length);
      } else if (target.id.startsWith(binaryViewerIDPrefix)) {
        id = target.id.slice(binaryViewerIDPrefix.length);
      } else {
        clickID = null;
        return;
      }

      if (prevID !== id) {
        if (prevID) {
          document.getElementById(nodeIDPrefix + prevID)?.querySelector(".details")?.classList.remove("highlight");
          document.getElementById(nodeIDPrefix + prevID)?.querySelector(".details")?.classList.remove("highlight-end");
          for (let i = id.indexOf("."); i != -1; i = prevID.indexOf(".", i + 1)) {
            const pid = prevID.slice(0, i);
            document.getElementById(nodeIDPrefix + pid)?.querySelector(".details")?.classList.remove("highlight");
          }
          document.getElementById(binaryViewerIDPrefix + prevID)?.classList.remove("highlight");
        }
        prevID = id;
        clickID = id;
        const newURL = new URL(window.location.toString());
        newURL.searchParams.set("hov", id);
        history.replaceState(null, "", newURL);

        document.getElementById(nodeIDPrefix + id)?.querySelector(".details")?.classList.add("highlight");
        document.getElementById(nodeIDPrefix + id)?.querySelector(".details")?.classList.add("highlight-end");
        for (let i = id.indexOf("."); i != -1; i = id.indexOf(".", i + 1)) {
          const pid = id.slice(0, i);
          document.getElementById(nodeIDPrefix + pid)?.querySelector(".details")?.classList.add("highlight");
        }
        document.getElementById(binaryViewerIDPrefix + id)?.classList.add("highlight");
      }
    }
  });

  const nodes = document.createElement("div");
  nodes.id = "nodes";

  const rhsWrapper = document.createElement("div");
  rhsWrapper.id = "rhs-wrapper";

  const binary = document.createElement("div");
  binary.id = "binary";
  rhsWrapper.appendChild(binary);

  const control = document.createElement("div");
  control.id = "control";

  const input = document.createElement("textarea");
  input.placeholder = "hex-encoded DNS message";
  control.appendChild(input);

  const wrapper = document.createElement("div");
  const buttonError = document.createElement("div");
  buttonError.hidden = true;
  buttonError.classList.add("control-error");

  const inspectButton = document.createElement("button");
  inspectButton.innerText = "inspect";
  inspectButton.addEventListener("click", () => {
    buttonError.hidden = true;
    const hex = input.value;
    if (hex.length % 2 != 0) {
      buttonError.innerText = `the amount of characters in not even (${hex.length})`;
      buttonError.hidden = false;
      return;
    }

    if (!/^[0-9A-Fa-f]+$/.test(hex)) {
      buttonError.innerText = 'not valid hex string';
      buttonError.hidden = false;
    }

    const bytes = new Uint8Array(hex.length / 2);

    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substring(i * 2, (i * 2) + 2), 16);
    }

    const msg = new Message(bytes);
    nodes.replaceChildren(renderNode(msg.Node, nodeIDPrefix + "0", 0));
    binary.replaceChildren(renderBinaryViewer(msg.Buf, 0, msg.Node, binaryViewerIDPrefix + "0"));
    prevID = null;
    clickID = null;

    const newURL = new URL(window.location.toString());
    newURL.searchParams.set("msg", hex);
    history.replaceState(null, "", newURL);
  });

  wrapper.appendChild(buttonError);
  wrapper.appendChild(inspectButton);
  control.appendChild(wrapper);

  rhsWrapper.appendChild(control);

  main.appendChild(nodes);
  main.appendChild(rhsWrapper);
  document.body.appendChild(main);

  const params = new URLSearchParams(window.location.search);
  const msg = params.get("msg");
  const hov = params.get("hov");
  if (msg) {
    input.value = msg;
    inspectButton.click();
    if (hov) {
      prevID = hov;
      clickID = hov;
      const bv = document.getElementById(binaryViewerIDPrefix + hov)!;
      const n = document.getElementById(nodeIDPrefix + hov);
      if (!n || !bv) {
        return;
      }

      scrollIntoViewIfNeeded(bv);
      bv.classList.add("highlight");

      scrollIntoViewIfNeeded(n);
      n.querySelector(".details")?.classList.add("highlight");
      n.querySelector(".details")?.classList.add("highlight-end");

      for (let i = hov.indexOf("."); i != -1; i = hov.indexOf(".", i + 1)) {
        const pid = hov.slice(0, i);
        document.getElementById(nodeIDPrefix + pid)?.querySelector(".details")?.classList.add("highlight");
      }
    }
  }
}

function renderNode(node: Node, id: string, bitOffset: number, bitField?: boolean): HTMLElement {
  const nodeDiv = document.createElement("div");
  nodeDiv.id = id;
  nodeDiv.classList.add("node");

  const details = document.createElement("div");
  details.append(`${node.Name}${!node.Invalid && node.Value ? `: ${node.Value}` : ""} `);

  const size = document.createElement("span");
  size.classList.add("node-size");
  size.innerText = `(${node.Length} ${bitField ? node.Length === 1 ? "Bit" : "Bits" : node.Length === 1 ? "Byte" : "Bytes"})`;
  details.append(size);

  details.append(" ");

  const offset = document.createElement("span");
  offset.classList.add("node-offset");
  offset.innerText = `(offset: ${Math.floor(bitOffset / 8)}${bitOffset % 8 !== 0 ? `:${bitOffset % 8}` : ""})`;
  details.append(offset);


  if (node.InsideNodes && node.InsideNodes.length != 0) {
    const hide = document.createElement("button");
    hide.classList.add("node-hide");
    hide.innerText = "^";
    details.append(hide);
  }
  if (node.Invalid) {
    nodeDiv.classList.add("node-invalid");
    if (node.Value) {
      details.append(` (${node.Value})`);
    }
  }
  details.classList.add("details");
  nodeDiv.appendChild(details);

  if (node.InsideNodes) {
    for (const [i, n] of node.InsideNodes.entries()) {
      nodeDiv.appendChild(renderNode(n, `${id}.${i}`, bitOffset, node.bitField));
      if (node.bitField) {
        bitOffset += n.Length;
      } else {
        bitOffset += n.Length * 8;
      }
    }
  }

  return nodeDiv;
}

function uint8ToHex(num: number): string {
  return ("00" + num.toString(16)).slice(-2).toUpperCase();
}

function uint8ToBin(num: number): string {
  return ("000000000" + num.toString(2)).slice(-8);
}

function renderBinaryViewer(buf: Uint8Array, offset: number, node: Node, id: string): HTMLElement {
  const span = document.createElement("span");
  span.id = id;

  if (node.InsideNodes === undefined || node.InsideNodes.length == 0) {
    buf.slice(offset, offset + node.Length).forEach((num) => {
      const byte = document.createElement("span");
      byte.classList.add("byte");
      byte.innerText = uint8ToHex(num);
      span.append(byte);
    }, "");
    return span;
  }

  if (node.bitField) {
    span.classList.add("wrapper");

    const bits = buf.slice(offset, offset + node.Length).reduce((prev, cur) => prev + uint8ToBin(cur), "");

    const bytes: HTMLSpanElement[] = [];
    for (let i = 0; i < node.Length; i++) {
      const s = document.createElement("span");
      s.classList.add("binary-byte");
      s.append("[[");
      bytes.push(s);
    }

    let bitsOffset = 0;
    let bytesIndex = 0;
    for (const [i, n] of node.InsideNodes.entries()) {
      let bitsLeft = n.Length;
      while (bitsLeft != 0) {
        let nodeLeftBits = (bytesIndex + 1) * 8 - bitsOffset;
        if (nodeLeftBits == 0) {
          bytes[bytesIndex].append("]]");
          bytesIndex++;
          nodeLeftBits = 8;
        }

        let count = bitsLeft;
        if (count > nodeLeftBits) {
          count = nodeLeftBits;
        }

        const s = document.createElement("span");
        s.id = `${id}.${i}`;
        s.innerText = bits.slice(bitsOffset, bitsOffset + count);
        bytes[bytesIndex].appendChild(s);
        bitsOffset += count;
        bitsLeft -= count;
      }
    }

    bytes[bytes.length - 1].append("]]");
    span.append(...bytes);
  } else {
    for (const [i, n] of node.InsideNodes.entries()) {
      span.appendChild(renderBinaryViewer(buf, offset, n, `${id}.${i}`));
      offset += n.Length;
    }
  }

  return span;
}

document.addEventListener("DOMContentLoaded", render);
