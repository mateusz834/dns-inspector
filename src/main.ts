export { };

type Node = {
  Name: string;
  Value?: string,

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
  node: Node;

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
        const rawName = raw.slice(0, length);
        for (let i = 0; rawName[i] != 0; i += rawName[i] + 1) {
          const label = rawName.slice(i + 1, i + 1 + rawName[i]);
          for (let j = 0; j < label.length; j++) {
            if (label[j] === '.'.charCodeAt(0)) {
              strName += "\\.";
            } else if (label[j] === '\\'.charCodeAt(0)) {
              strName += "\\\\";
            } else if (label[j] < '!'.charCodeAt(0) || label[j] > '~'.charCodeAt(0)) {
              strName += "\\" + ("000" + label[j]).slice(-3);
            } else {
              strName += String.fromCharCode(label[j]);
            }
          }
          strName += ".";
        }

        this.node = {
          Name: "Name",
          Value: strName,
          Length: this.nameLengthNoFollowPtr
        };
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
        this.name.node,
        { Name: "Type", Value: this.type.toString(), Length: 2 },
        { Name: "Class", Value: this.class.toString(), Length: 2 },
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

  constructor(msg: Uint8Array, offset: number) {
    try {
      this.name = new Name(msg, offset);
    } catch (err) {
      if (err instanceof Error) {
        throw new Error(`invalid resource header, ${err.message}`);
      }
      throw new Error("internal resource header");
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

    this.node = {
      Name: "Resource",
      Length: this.resourceLength,
      InsideNodes: [
        this.name.node,
        { Name: "Type", Value: this.type.toString(), Length: 2 },
        { Name: "Class", Value: this.class.toString(), Length: 2 },
        { Name: "TTL", Value: this.ttl.toString(), Length: 4 },
        { Name: "Length", Value: this.length.toString(), Length: 2 },
        { Name: "Resource Data", Length: this.length },
      ]
    };
  }
}

class Message {
  Buf: Uint8Array;
  Node: Node;
  Header: Header;

  constructor(msg: Uint8Array) {
    if (msg.length < 12) {
      throw new Error("dns message too short, it does not contain a header");
    }
    this.Header = new Header(msg.slice(0, 12));
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

    this.Node = {
      Name: "Message",
      Length: msg.length,
      InsideNodes: [
        this.Header.asNode(),
        questionsNode,
        answersNode,
        authoritiesNode,
        additionalsNode,
      ],
    };


    let offset = 12;
    for (let i = 0; i < this.Header.QDCount; i++) {
      const q = new Queston(msg, offset);
      offset += q.questionLength;
      questionsNode.Length += q.questionLength;
      questionsNode.InsideNodes?.push(q.node);
    }

    for (let i = 0; i < this.Header.ANCount; i++) {
      const q = new Resource(msg, offset);
      offset += q.resourceLength;
      answersNode.Length += q.resourceLength;
      answersNode.InsideNodes?.push(q.node);
    }

    for (let i = 0; i < this.Header.NSCount; i++) {
      const q = new Resource(msg, offset);
      offset += q.resourceLength;
      authoritiesNode.Length += q.resourceLength;
      authoritiesNode.InsideNodes?.push(q.node);
    }

    for (let i = 0; i < this.Header.ARCount; i++) {
      const q = new Resource(msg, offset);
      offset += q.resourceLength;
      additionalsNode.Length += q.resourceLength;
      additionalsNode.InsideNodes?.push(q.node);
    }
  }
}

function render() {
  const msg = new Message(new Uint8Array(
    [
      1, 128, 8, 131, 0, 1, 0, 1, 0, 0, 0, 0,
      3, 67, 67, 67, 0, 1, 0, 2, 3,
      0xC0, 12, 1, 0, 2, 3, 0, 0, 0, 0, 0, 3,
      1, 2, 3,
    ]
  ));

  const nodeIDPrefix = "node-";
  const binaryViewerIDPrefix = "viewer-";

  let prevID: string | null = null;

  const main = document.createElement("div");
  main.id = "main";
  main.addEventListener("mousemove", (e) => {
    let target = e.target;
    if (target instanceof HTMLElement) {
      if (target.id == "") {
        target = target.parentNode;
        if (target === null || !(target instanceof HTMLElement)) {
          return;
        }
      }

      let id = "";
      if (target.id.startsWith(nodeIDPrefix)) {
        id = target.id.slice(nodeIDPrefix.length);
      } else if (target.id.startsWith(binaryViewerIDPrefix)) {
        id = target.id.slice(binaryViewerIDPrefix.length);
      } else {
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
  nodes.appendChild(renderNode(msg.Node, nodeIDPrefix + "0"));

  const binary = document.createElement("div");
  binary.id = "binary";
  binary.appendChild(renderBinaryViewer(msg.Buf, 0, msg.Node, binaryViewerIDPrefix + "0"));

  main.appendChild(nodes);
  main.appendChild(binary);
  document.body.appendChild(main);
}

function renderNode(node: Node, id: string, bitField?: boolean): HTMLElement {
  const nodeDiv = document.createElement("div");
  nodeDiv.id = id;
  nodeDiv.classList.add("node");

  const details = document.createElement("div");
  const size = `${node.Length} ${bitField ? node.Length === 1 ? "Bit" : "Bits" : node.Length === 1 ? "Bytes" : "Byte"}`;
  details.innerHTML = `${node.Name} ${node.Value ? `: ${node.Value}` : ""} <span class="node-size">(${size})</span>`;
  details.classList.add("details");
  nodeDiv.appendChild(details);

  if (node.InsideNodes) {
    for (const [i, n] of node.InsideNodes.entries()) {
      nodeDiv.appendChild(renderNode(n, `${id}.${i}`, node.bitField));
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
    span.innerHTML = buf.slice(offset, offset + node.Length).reduce((str, num) => str + "<span class='byte'>" + uint8ToHex(num) + "</span>", "");
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

