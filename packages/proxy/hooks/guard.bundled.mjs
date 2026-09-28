#!/usr/bin/env node
// AUTO-GENERATED from guard.mjs by scripts/bundle-hooks.mjs — DO NOT EDIT.
// Edit guard.mjs and run `pnpm --filter @solongate/proxy build:hooks` to regenerate.
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/json.js
var require_json = __commonJS({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/json.js"(exports, module) {
    function isValidJSON(str) {
      if (typeof str !== "string") {
        return;
      }
      try {
        JSON.parse(str);
        return true;
      } catch (err) {
        if (err instanceof SyntaxError) {
          return false;
        }
        throw err;
      }
    }
    module.exports = {
      "json.is_valid": isValidJSON
    };
  }
});

// ../../node_modules/.pnpm/sprintf-js@1.1.3/node_modules/sprintf-js/src/sprintf.js
var require_sprintf = __commonJS({
  "../../node_modules/.pnpm/sprintf-js@1.1.3/node_modules/sprintf-js/src/sprintf.js"(exports) {
    !function() {
      "use strict";
      var re = {
        not_string: /[^s]/,
        not_bool: /[^t]/,
        not_type: /[^T]/,
        not_primitive: /[^v]/,
        number: /[diefg]/,
        numeric_arg: /[bcdiefguxX]/,
        json: /[j]/,
        not_json: /[^j]/,
        text: /^[^\x25]+/,
        modulo: /^\x25{2}/,
        placeholder: /^\x25(?:([1-9]\d*)\$|\(([^)]+)\))?(\+)?(0|'[^$])?(-)?(\d+)?(?:\.(\d+))?([b-gijostTuvxX])/,
        key: /^([a-z_][a-z_\d]*)/i,
        key_access: /^\.([a-z_][a-z_\d]*)/i,
        index_access: /^\[(\d+)\]/,
        sign: /^[+-]/
      };
      function sprintf(key) {
        return sprintf_format(sprintf_parse(key), arguments);
      }
      function vsprintf(fmt, argv) {
        return sprintf.apply(null, [fmt].concat(argv || []));
      }
      function sprintf_format(parse_tree, argv) {
        var cursor = 1, tree_length = parse_tree.length, arg, output = "", i, k, ph, pad, pad_character, pad_length, is_positive, sign;
        for (i = 0; i < tree_length; i++) {
          if (typeof parse_tree[i] === "string") {
            output += parse_tree[i];
          } else if (typeof parse_tree[i] === "object") {
            ph = parse_tree[i];
            if (ph.keys) {
              arg = argv[cursor];
              for (k = 0; k < ph.keys.length; k++) {
                if (arg == void 0) {
                  throw new Error(sprintf('[sprintf] Cannot access property "%s" of undefined value "%s"', ph.keys[k], ph.keys[k - 1]));
                }
                arg = arg[ph.keys[k]];
              }
            } else if (ph.param_no) {
              arg = argv[ph.param_no];
            } else {
              arg = argv[cursor++];
            }
            if (re.not_type.test(ph.type) && re.not_primitive.test(ph.type) && arg instanceof Function) {
              arg = arg();
            }
            if (re.numeric_arg.test(ph.type) && (typeof arg !== "number" && isNaN(arg))) {
              throw new TypeError(sprintf("[sprintf] expecting number but found %T", arg));
            }
            if (re.number.test(ph.type)) {
              is_positive = arg >= 0;
            }
            switch (ph.type) {
              case "b":
                arg = parseInt(arg, 10).toString(2);
                break;
              case "c":
                arg = String.fromCharCode(parseInt(arg, 10));
                break;
              case "d":
              case "i":
                arg = parseInt(arg, 10);
                break;
              case "j":
                arg = JSON.stringify(arg, null, ph.width ? parseInt(ph.width) : 0);
                break;
              case "e":
                arg = ph.precision ? parseFloat(arg).toExponential(ph.precision) : parseFloat(arg).toExponential();
                break;
              case "f":
                arg = ph.precision ? parseFloat(arg).toFixed(ph.precision) : parseFloat(arg);
                break;
              case "g":
                arg = ph.precision ? String(Number(arg.toPrecision(ph.precision))) : parseFloat(arg);
                break;
              case "o":
                arg = (parseInt(arg, 10) >>> 0).toString(8);
                break;
              case "s":
                arg = String(arg);
                arg = ph.precision ? arg.substring(0, ph.precision) : arg;
                break;
              case "t":
                arg = String(!!arg);
                arg = ph.precision ? arg.substring(0, ph.precision) : arg;
                break;
              case "T":
                arg = Object.prototype.toString.call(arg).slice(8, -1).toLowerCase();
                arg = ph.precision ? arg.substring(0, ph.precision) : arg;
                break;
              case "u":
                arg = parseInt(arg, 10) >>> 0;
                break;
              case "v":
                arg = arg.valueOf();
                arg = ph.precision ? arg.substring(0, ph.precision) : arg;
                break;
              case "x":
                arg = (parseInt(arg, 10) >>> 0).toString(16);
                break;
              case "X":
                arg = (parseInt(arg, 10) >>> 0).toString(16).toUpperCase();
                break;
            }
            if (re.json.test(ph.type)) {
              output += arg;
            } else {
              if (re.number.test(ph.type) && (!is_positive || ph.sign)) {
                sign = is_positive ? "+" : "-";
                arg = arg.toString().replace(re.sign, "");
              } else {
                sign = "";
              }
              pad_character = ph.pad_char ? ph.pad_char === "0" ? "0" : ph.pad_char.charAt(1) : " ";
              pad_length = ph.width - (sign + arg).length;
              pad = ph.width ? pad_length > 0 ? pad_character.repeat(pad_length) : "" : "";
              output += ph.align ? sign + arg + pad : pad_character === "0" ? sign + pad + arg : pad + sign + arg;
            }
          }
        }
        return output;
      }
      var sprintf_cache = /* @__PURE__ */ Object.create(null);
      function sprintf_parse(fmt) {
        if (sprintf_cache[fmt]) {
          return sprintf_cache[fmt];
        }
        var _fmt = fmt, match, parse_tree = [], arg_names = 0;
        while (_fmt) {
          if ((match = re.text.exec(_fmt)) !== null) {
            parse_tree.push(match[0]);
          } else if ((match = re.modulo.exec(_fmt)) !== null) {
            parse_tree.push("%");
          } else if ((match = re.placeholder.exec(_fmt)) !== null) {
            if (match[2]) {
              arg_names |= 1;
              var field_list = [], replacement_field = match[2], field_match = [];
              if ((field_match = re.key.exec(replacement_field)) !== null) {
                field_list.push(field_match[1]);
                while ((replacement_field = replacement_field.substring(field_match[0].length)) !== "") {
                  if ((field_match = re.key_access.exec(replacement_field)) !== null) {
                    field_list.push(field_match[1]);
                  } else if ((field_match = re.index_access.exec(replacement_field)) !== null) {
                    field_list.push(field_match[1]);
                  } else {
                    throw new SyntaxError("[sprintf] failed to parse named argument key");
                  }
                }
              } else {
                throw new SyntaxError("[sprintf] failed to parse named argument key");
              }
              match[2] = field_list;
            } else {
              arg_names |= 2;
            }
            if (arg_names === 3) {
              throw new Error("[sprintf] mixing positional and named placeholders is not (yet) supported");
            }
            parse_tree.push(
              {
                placeholder: match[0],
                param_no: match[1],
                keys: match[2],
                sign: match[3],
                pad_char: match[4],
                align: match[5],
                width: match[6],
                precision: match[7],
                type: match[8]
              }
            );
          } else {
            throw new SyntaxError("[sprintf] unexpected placeholder");
          }
          _fmt = _fmt.substring(match[0].length);
        }
        return sprintf_cache[fmt] = parse_tree;
      }
      if (typeof exports !== "undefined") {
        exports["sprintf"] = sprintf;
        exports["vsprintf"] = vsprintf;
      }
      if (typeof window !== "undefined") {
        window["sprintf"] = sprintf;
        window["vsprintf"] = vsprintf;
        if (typeof define === "function" && define["amd"]) {
          define(function() {
            return {
              "sprintf": sprintf,
              "vsprintf": vsprintf
            };
          });
        }
      }
    }();
  }
});

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/strings.js
var require_strings = __commonJS({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/strings.js"(exports, module) {
    var vsprintf = require_sprintf().vsprintf;
    var sprintf = (s, values) => vsprintf(s, values);
    module.exports = { sprintf };
  }
});

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/regex.js
var require_regex = __commonJS({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/regex.js"(exports, module) {
    var regexSplit = (pattern, s) => s.split(RegExp(pattern));
    module.exports = { "regex.split": regexSplit };
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/PlainValue-516d5bc2.js
var require_PlainValue_516d5bc2 = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/PlainValue-516d5bc2.js"(exports) {
    "use strict";
    var Char = {
      ANCHOR: "&",
      COMMENT: "#",
      TAG: "!",
      DIRECTIVES_END: "-",
      DOCUMENT_END: "."
    };
    var Type = {
      ALIAS: "ALIAS",
      BLANK_LINE: "BLANK_LINE",
      BLOCK_FOLDED: "BLOCK_FOLDED",
      BLOCK_LITERAL: "BLOCK_LITERAL",
      COMMENT: "COMMENT",
      DIRECTIVE: "DIRECTIVE",
      DOCUMENT: "DOCUMENT",
      FLOW_MAP: "FLOW_MAP",
      FLOW_SEQ: "FLOW_SEQ",
      MAP: "MAP",
      MAP_KEY: "MAP_KEY",
      MAP_VALUE: "MAP_VALUE",
      PLAIN: "PLAIN",
      QUOTE_DOUBLE: "QUOTE_DOUBLE",
      QUOTE_SINGLE: "QUOTE_SINGLE",
      SEQ: "SEQ",
      SEQ_ITEM: "SEQ_ITEM"
    };
    var defaultTagPrefix = "tag:yaml.org,2002:";
    var defaultTags = {
      MAP: "tag:yaml.org,2002:map",
      SEQ: "tag:yaml.org,2002:seq",
      STR: "tag:yaml.org,2002:str"
    };
    function findLineStarts(src) {
      const ls = [0];
      let offset = src.indexOf("\n");
      while (offset !== -1) {
        offset += 1;
        ls.push(offset);
        offset = src.indexOf("\n", offset);
      }
      return ls;
    }
    function getSrcInfo(cst) {
      let lineStarts, src;
      if (typeof cst === "string") {
        lineStarts = findLineStarts(cst);
        src = cst;
      } else {
        if (Array.isArray(cst))
          cst = cst[0];
        if (cst && cst.context) {
          if (!cst.lineStarts)
            cst.lineStarts = findLineStarts(cst.context.src);
          lineStarts = cst.lineStarts;
          src = cst.context.src;
        }
      }
      return {
        lineStarts,
        src
      };
    }
    function getLinePos(offset, cst) {
      if (typeof offset !== "number" || offset < 0)
        return null;
      const {
        lineStarts,
        src
      } = getSrcInfo(cst);
      if (!lineStarts || !src || offset > src.length)
        return null;
      for (let i = 0; i < lineStarts.length; ++i) {
        const start = lineStarts[i];
        if (offset < start) {
          return {
            line: i,
            col: offset - lineStarts[i - 1] + 1
          };
        }
        if (offset === start)
          return {
            line: i + 1,
            col: 1
          };
      }
      const line = lineStarts.length;
      return {
        line,
        col: offset - lineStarts[line - 1] + 1
      };
    }
    function getLine(line, cst) {
      const {
        lineStarts,
        src
      } = getSrcInfo(cst);
      if (!lineStarts || !(line >= 1) || line > lineStarts.length)
        return null;
      const start = lineStarts[line - 1];
      let end = lineStarts[line];
      while (end && end > start && src[end - 1] === "\n")
        --end;
      return src.slice(start, end);
    }
    function getPrettyContext({
      start,
      end
    }, cst, maxWidth = 80) {
      let src = getLine(start.line, cst);
      if (!src)
        return null;
      let {
        col
      } = start;
      if (src.length > maxWidth) {
        if (col <= maxWidth - 10) {
          src = src.substr(0, maxWidth - 1) + "\u2026";
        } else {
          const halfWidth = Math.round(maxWidth / 2);
          if (src.length > col + halfWidth)
            src = src.substr(0, col + halfWidth - 1) + "\u2026";
          col -= src.length - maxWidth;
          src = "\u2026" + src.substr(1 - maxWidth);
        }
      }
      let errLen = 1;
      let errEnd = "";
      if (end) {
        if (end.line === start.line && col + (end.col - start.col) <= maxWidth + 1) {
          errLen = end.col - start.col;
        } else {
          errLen = Math.min(src.length + 1, maxWidth) - col;
          errEnd = "\u2026";
        }
      }
      const offset = col > 1 ? " ".repeat(col - 1) : "";
      const err = "^".repeat(errLen);
      return `${src}
${offset}${err}${errEnd}`;
    }
    var Range = class _Range {
      static copy(orig) {
        return new _Range(orig.start, orig.end);
      }
      constructor(start, end) {
        this.start = start;
        this.end = end || start;
      }
      isEmpty() {
        return typeof this.start !== "number" || !this.end || this.end <= this.start;
      }
      /**
       * Set `origStart` and `origEnd` to point to the original source range for
       * this node, which may differ due to dropped CR characters.
       *
       * @param {number[]} cr - Positions of dropped CR characters
       * @param {number} offset - Starting index of `cr` from the last call
       * @returns {number} - The next offset, matching the one found for `origStart`
       */
      setOrigRange(cr, offset) {
        const {
          start,
          end
        } = this;
        if (cr.length === 0 || end <= cr[0]) {
          this.origStart = start;
          this.origEnd = end;
          return offset;
        }
        let i = offset;
        while (i < cr.length) {
          if (cr[i] > start)
            break;
          else
            ++i;
        }
        this.origStart = start + i;
        const nextOffset = i;
        while (i < cr.length) {
          if (cr[i] >= end)
            break;
          else
            ++i;
        }
        this.origEnd = end + i;
        return nextOffset;
      }
    };
    var Node = class _Node {
      static addStringTerminator(src, offset, str) {
        if (str[str.length - 1] === "\n")
          return str;
        const next = _Node.endOfWhiteSpace(src, offset);
        return next >= src.length || src[next] === "\n" ? str + "\n" : str;
      }
      // ^(---|...)
      static atDocumentBoundary(src, offset, sep) {
        const ch0 = src[offset];
        if (!ch0)
          return true;
        const prev = src[offset - 1];
        if (prev && prev !== "\n")
          return false;
        if (sep) {
          if (ch0 !== sep)
            return false;
        } else {
          if (ch0 !== Char.DIRECTIVES_END && ch0 !== Char.DOCUMENT_END)
            return false;
        }
        const ch1 = src[offset + 1];
        const ch2 = src[offset + 2];
        if (ch1 !== ch0 || ch2 !== ch0)
          return false;
        const ch3 = src[offset + 3];
        return !ch3 || ch3 === "\n" || ch3 === "	" || ch3 === " ";
      }
      static endOfIdentifier(src, offset) {
        let ch = src[offset];
        const isVerbatim = ch === "<";
        const notOk = isVerbatim ? ["\n", "	", " ", ">"] : ["\n", "	", " ", "[", "]", "{", "}", ","];
        while (ch && notOk.indexOf(ch) === -1)
          ch = src[offset += 1];
        if (isVerbatim && ch === ">")
          offset += 1;
        return offset;
      }
      static endOfIndent(src, offset) {
        let ch = src[offset];
        while (ch === " ")
          ch = src[offset += 1];
        return offset;
      }
      static endOfLine(src, offset) {
        let ch = src[offset];
        while (ch && ch !== "\n")
          ch = src[offset += 1];
        return offset;
      }
      static endOfWhiteSpace(src, offset) {
        let ch = src[offset];
        while (ch === "	" || ch === " ")
          ch = src[offset += 1];
        return offset;
      }
      static startOfLine(src, offset) {
        let ch = src[offset - 1];
        if (ch === "\n")
          return offset;
        while (ch && ch !== "\n")
          ch = src[offset -= 1];
        return offset + 1;
      }
      /**
       * End of indentation, or null if the line's indent level is not more
       * than `indent`
       *
       * @param {string} src
       * @param {number} indent
       * @param {number} lineStart
       * @returns {?number}
       */
      static endOfBlockIndent(src, indent, lineStart) {
        const inEnd = _Node.endOfIndent(src, lineStart);
        if (inEnd > lineStart + indent) {
          return inEnd;
        } else {
          const wsEnd = _Node.endOfWhiteSpace(src, inEnd);
          const ch = src[wsEnd];
          if (!ch || ch === "\n")
            return wsEnd;
        }
        return null;
      }
      static atBlank(src, offset, endAsBlank) {
        const ch = src[offset];
        return ch === "\n" || ch === "	" || ch === " " || endAsBlank && !ch;
      }
      static nextNodeIsIndented(ch, indentDiff, indicatorAsIndent) {
        if (!ch || indentDiff < 0)
          return false;
        if (indentDiff > 0)
          return true;
        return indicatorAsIndent && ch === "-";
      }
      // should be at line or string end, or at next non-whitespace char
      static normalizeOffset(src, offset) {
        const ch = src[offset];
        return !ch ? offset : ch !== "\n" && src[offset - 1] === "\n" ? offset - 1 : _Node.endOfWhiteSpace(src, offset);
      }
      // fold single newline into space, multiple newlines to N - 1 newlines
      // presumes src[offset] === '\n'
      static foldNewline(src, offset, indent) {
        let inCount = 0;
        let error = false;
        let fold = "";
        let ch = src[offset + 1];
        while (ch === " " || ch === "	" || ch === "\n") {
          switch (ch) {
            case "\n":
              inCount = 0;
              offset += 1;
              fold += "\n";
              break;
            case "	":
              if (inCount <= indent)
                error = true;
              offset = _Node.endOfWhiteSpace(src, offset + 2) - 1;
              break;
            case " ":
              inCount += 1;
              offset += 1;
              break;
          }
          ch = src[offset + 1];
        }
        if (!fold)
          fold = " ";
        if (ch && inCount <= indent)
          error = true;
        return {
          fold,
          offset,
          error
        };
      }
      constructor(type, props, context) {
        Object.defineProperty(this, "context", {
          value: context || null,
          writable: true
        });
        this.error = null;
        this.range = null;
        this.valueRange = null;
        this.props = props || [];
        this.type = type;
        this.value = null;
      }
      getPropValue(idx, key, skipKey) {
        if (!this.context)
          return null;
        const {
          src
        } = this.context;
        const prop = this.props[idx];
        return prop && src[prop.start] === key ? src.slice(prop.start + (skipKey ? 1 : 0), prop.end) : null;
      }
      get anchor() {
        for (let i = 0; i < this.props.length; ++i) {
          const anchor = this.getPropValue(i, Char.ANCHOR, true);
          if (anchor != null)
            return anchor;
        }
        return null;
      }
      get comment() {
        const comments = [];
        for (let i = 0; i < this.props.length; ++i) {
          const comment = this.getPropValue(i, Char.COMMENT, true);
          if (comment != null)
            comments.push(comment);
        }
        return comments.length > 0 ? comments.join("\n") : null;
      }
      commentHasRequiredWhitespace(start) {
        const {
          src
        } = this.context;
        if (this.header && start === this.header.end)
          return false;
        if (!this.valueRange)
          return false;
        const {
          end
        } = this.valueRange;
        return start !== end || _Node.atBlank(src, end - 1);
      }
      get hasComment() {
        if (this.context) {
          const {
            src
          } = this.context;
          for (let i = 0; i < this.props.length; ++i) {
            if (src[this.props[i].start] === Char.COMMENT)
              return true;
          }
        }
        return false;
      }
      get hasProps() {
        if (this.context) {
          const {
            src
          } = this.context;
          for (let i = 0; i < this.props.length; ++i) {
            if (src[this.props[i].start] !== Char.COMMENT)
              return true;
          }
        }
        return false;
      }
      get includesTrailingLines() {
        return false;
      }
      get jsonLike() {
        const jsonLikeTypes = [Type.FLOW_MAP, Type.FLOW_SEQ, Type.QUOTE_DOUBLE, Type.QUOTE_SINGLE];
        return jsonLikeTypes.indexOf(this.type) !== -1;
      }
      get rangeAsLinePos() {
        if (!this.range || !this.context)
          return void 0;
        const start = getLinePos(this.range.start, this.context.root);
        if (!start)
          return void 0;
        const end = getLinePos(this.range.end, this.context.root);
        return {
          start,
          end
        };
      }
      get rawValue() {
        if (!this.valueRange || !this.context)
          return null;
        const {
          start,
          end
        } = this.valueRange;
        return this.context.src.slice(start, end);
      }
      get tag() {
        for (let i = 0; i < this.props.length; ++i) {
          const tag = this.getPropValue(i, Char.TAG, false);
          if (tag != null) {
            if (tag[1] === "<") {
              return {
                verbatim: tag.slice(2, -1)
              };
            } else {
              const [_, handle, suffix] = tag.match(/^(.*!)([^!]*)$/);
              return {
                handle,
                suffix
              };
            }
          }
        }
        return null;
      }
      get valueRangeContainsNewline() {
        if (!this.valueRange || !this.context)
          return false;
        const {
          start,
          end
        } = this.valueRange;
        const {
          src
        } = this.context;
        for (let i = start; i < end; ++i) {
          if (src[i] === "\n")
            return true;
        }
        return false;
      }
      parseComment(start) {
        const {
          src
        } = this.context;
        if (src[start] === Char.COMMENT) {
          const end = _Node.endOfLine(src, start + 1);
          const commentRange = new Range(start, end);
          this.props.push(commentRange);
          return end;
        }
        return start;
      }
      /**
       * Populates the `origStart` and `origEnd` values of all ranges for this
       * node. Extended by child classes to handle descendant nodes.
       *
       * @param {number[]} cr - Positions of dropped CR characters
       * @param {number} offset - Starting index of `cr` from the last call
       * @returns {number} - The next offset, matching the one found for `origStart`
       */
      setOrigRanges(cr, offset) {
        if (this.range)
          offset = this.range.setOrigRange(cr, offset);
        if (this.valueRange)
          this.valueRange.setOrigRange(cr, offset);
        this.props.forEach((prop) => prop.setOrigRange(cr, offset));
        return offset;
      }
      toString() {
        const {
          context: {
            src
          },
          range,
          value
        } = this;
        if (value != null)
          return value;
        const str = src.slice(range.start, range.end);
        return _Node.addStringTerminator(src, range.end, str);
      }
    };
    var YAMLError = class extends Error {
      constructor(name, source, message) {
        if (!message || !(source instanceof Node))
          throw new Error(`Invalid arguments for new ${name}`);
        super();
        this.name = name;
        this.message = message;
        this.source = source;
      }
      makePretty() {
        if (!this.source)
          return;
        this.nodeType = this.source.type;
        const cst = this.source.context && this.source.context.root;
        if (typeof this.offset === "number") {
          this.range = new Range(this.offset, this.offset + 1);
          const start = cst && getLinePos(this.offset, cst);
          if (start) {
            const end = {
              line: start.line,
              col: start.col + 1
            };
            this.linePos = {
              start,
              end
            };
          }
          delete this.offset;
        } else {
          this.range = this.source.range;
          this.linePos = this.source.rangeAsLinePos;
        }
        if (this.linePos) {
          const {
            line,
            col
          } = this.linePos.start;
          this.message += ` at line ${line}, column ${col}`;
          const ctx = cst && getPrettyContext(this.linePos, cst);
          if (ctx)
            this.message += `:

${ctx}
`;
        }
        delete this.source;
      }
    };
    var YAMLReferenceError = class extends YAMLError {
      constructor(source, message) {
        super("YAMLReferenceError", source, message);
      }
    };
    var YAMLSemanticError = class extends YAMLError {
      constructor(source, message) {
        super("YAMLSemanticError", source, message);
      }
    };
    var YAMLSyntaxError = class extends YAMLError {
      constructor(source, message) {
        super("YAMLSyntaxError", source, message);
      }
    };
    var YAMLWarning = class extends YAMLError {
      constructor(source, message) {
        super("YAMLWarning", source, message);
      }
    };
    function _defineProperty(e, r, t) {
      return (r = _toPropertyKey(r)) in e ? Object.defineProperty(e, r, {
        value: t,
        enumerable: true,
        configurable: true,
        writable: true
      }) : e[r] = t, e;
    }
    function _toPrimitive(t, r) {
      if ("object" != typeof t || !t)
        return t;
      var e = t[Symbol.toPrimitive];
      if (void 0 !== e) {
        var i = e.call(t, r || "default");
        if ("object" != typeof i)
          return i;
        throw new TypeError("@@toPrimitive must return a primitive value.");
      }
      return ("string" === r ? String : Number)(t);
    }
    function _toPropertyKey(t) {
      var i = _toPrimitive(t, "string");
      return "symbol" == typeof i ? i : i + "";
    }
    var PlainValue = class _PlainValue extends Node {
      static endOfLine(src, start, inFlow) {
        let ch = src[start];
        let offset = start;
        while (ch && ch !== "\n") {
          if (inFlow && (ch === "[" || ch === "]" || ch === "{" || ch === "}" || ch === ","))
            break;
          const next = src[offset + 1];
          if (ch === ":" && (!next || next === "\n" || next === "	" || next === " " || inFlow && next === ","))
            break;
          if ((ch === " " || ch === "	") && next === "#")
            break;
          offset += 1;
          ch = next;
        }
        return offset;
      }
      get strValue() {
        if (!this.valueRange || !this.context)
          return null;
        let {
          start,
          end
        } = this.valueRange;
        const {
          src
        } = this.context;
        let ch = src[end - 1];
        while (start < end && (ch === "\n" || ch === "	" || ch === " "))
          ch = src[--end - 1];
        let str = "";
        for (let i = start; i < end; ++i) {
          const ch2 = src[i];
          if (ch2 === "\n") {
            const {
              fold,
              offset
            } = Node.foldNewline(src, i, -1);
            str += fold;
            i = offset;
          } else if (ch2 === " " || ch2 === "	") {
            const wsStart = i;
            let next = src[i + 1];
            while (i < end && (next === " " || next === "	")) {
              i += 1;
              next = src[i + 1];
            }
            if (next !== "\n")
              str += i > wsStart ? src.slice(wsStart, i + 1) : ch2;
          } else {
            str += ch2;
          }
        }
        const ch0 = src[start];
        switch (ch0) {
          case "	": {
            const msg = "Plain value cannot start with a tab character";
            const errors = [new YAMLSemanticError(this, msg)];
            return {
              errors,
              str
            };
          }
          case "@":
          case "`": {
            const msg = `Plain value cannot start with reserved character ${ch0}`;
            const errors = [new YAMLSemanticError(this, msg)];
            return {
              errors,
              str
            };
          }
          default:
            return str;
        }
      }
      parseBlockValue(start) {
        const {
          indent,
          inFlow,
          src
        } = this.context;
        let offset = start;
        let valueEnd = start;
        for (let ch = src[offset]; ch === "\n"; ch = src[offset]) {
          if (Node.atDocumentBoundary(src, offset + 1))
            break;
          const end = Node.endOfBlockIndent(src, indent, offset + 1);
          if (end === null || src[end] === "#")
            break;
          if (src[end] === "\n") {
            offset = end;
          } else {
            valueEnd = _PlainValue.endOfLine(src, end, inFlow);
            offset = valueEnd;
          }
        }
        if (this.valueRange.isEmpty())
          this.valueRange.start = start;
        this.valueRange.end = valueEnd;
        return valueEnd;
      }
      /**
       * Parses a plain value from the source
       *
       * Accepted forms are:
       * ```
       * #comment
       *
       * first line
       *
       * first line #comment
       *
       * first line
       * block
       * lines
       *
       * #comment
       * block
       * lines
       * ```
       * where block lines are empty or have an indent level greater than `indent`.
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this scalar, may be `\n`
       */
      parse(context, start) {
        this.context = context;
        const {
          inFlow,
          src
        } = context;
        let offset = start;
        const ch = src[offset];
        if (ch && ch !== "#" && ch !== "\n") {
          offset = _PlainValue.endOfLine(src, start, inFlow);
        }
        this.valueRange = new Range(start, offset);
        offset = Node.endOfWhiteSpace(src, offset);
        offset = this.parseComment(offset);
        if (!this.hasComment || this.valueRange.isEmpty()) {
          offset = this.parseBlockValue(offset);
        }
        return offset;
      }
    };
    exports.Char = Char;
    exports.Node = Node;
    exports.PlainValue = PlainValue;
    exports.Range = Range;
    exports.Type = Type;
    exports.YAMLError = YAMLError;
    exports.YAMLReferenceError = YAMLReferenceError;
    exports.YAMLSemanticError = YAMLSemanticError;
    exports.YAMLSyntaxError = YAMLSyntaxError;
    exports.YAMLWarning = YAMLWarning;
    exports._defineProperty = _defineProperty;
    exports.defaultTagPrefix = defaultTagPrefix;
    exports.defaultTags = defaultTags;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/parse-cst.js
var require_parse_cst = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/parse-cst.js"(exports) {
    "use strict";
    var PlainValue = require_PlainValue_516d5bc2();
    var BlankLine = class extends PlainValue.Node {
      constructor() {
        super(PlainValue.Type.BLANK_LINE);
      }
      /* istanbul ignore next */
      get includesTrailingLines() {
        return true;
      }
      /**
       * Parses a blank line from the source
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first \n character
       * @returns {number} - Index of the character after this
       */
      parse(context, start) {
        this.context = context;
        this.range = new PlainValue.Range(start, start + 1);
        return start + 1;
      }
    };
    var CollectionItem = class extends PlainValue.Node {
      constructor(type, props) {
        super(type, props);
        this.node = null;
      }
      get includesTrailingLines() {
        return !!this.node && this.node.includesTrailingLines;
      }
      /**
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this
       */
      parse(context, start) {
        this.context = context;
        const {
          parseNode,
          src
        } = context;
        let {
          atLineStart,
          lineStart
        } = context;
        if (!atLineStart && this.type === PlainValue.Type.SEQ_ITEM)
          this.error = new PlainValue.YAMLSemanticError(this, "Sequence items must not have preceding content on the same line");
        const indent = atLineStart ? start - lineStart : context.indent;
        let offset = PlainValue.Node.endOfWhiteSpace(src, start + 1);
        let ch = src[offset];
        const inlineComment = ch === "#";
        const comments = [];
        let blankLine = null;
        while (ch === "\n" || ch === "#") {
          if (ch === "#") {
            const end2 = PlainValue.Node.endOfLine(src, offset + 1);
            comments.push(new PlainValue.Range(offset, end2));
            offset = end2;
          } else {
            atLineStart = true;
            lineStart = offset + 1;
            const wsEnd = PlainValue.Node.endOfWhiteSpace(src, lineStart);
            if (src[wsEnd] === "\n" && comments.length === 0) {
              blankLine = new BlankLine();
              lineStart = blankLine.parse({
                src
              }, lineStart);
            }
            offset = PlainValue.Node.endOfIndent(src, lineStart);
          }
          ch = src[offset];
        }
        if (PlainValue.Node.nextNodeIsIndented(ch, offset - (lineStart + indent), this.type !== PlainValue.Type.SEQ_ITEM)) {
          this.node = parseNode({
            atLineStart,
            inCollection: false,
            indent,
            lineStart,
            parent: this
          }, offset);
        } else if (ch && lineStart > start + 1) {
          offset = lineStart - 1;
        }
        if (this.node) {
          if (blankLine) {
            const items = context.parent.items || context.parent.contents;
            if (items)
              items.push(blankLine);
          }
          if (comments.length)
            Array.prototype.push.apply(this.props, comments);
          offset = this.node.range.end;
        } else {
          if (inlineComment) {
            const c = comments[0];
            this.props.push(c);
            offset = c.end;
          } else {
            offset = PlainValue.Node.endOfLine(src, start + 1);
          }
        }
        const end = this.node ? this.node.valueRange.end : offset;
        this.valueRange = new PlainValue.Range(start, end);
        return offset;
      }
      setOrigRanges(cr, offset) {
        offset = super.setOrigRanges(cr, offset);
        return this.node ? this.node.setOrigRanges(cr, offset) : offset;
      }
      toString() {
        const {
          context: {
            src
          },
          node,
          range,
          value
        } = this;
        if (value != null)
          return value;
        const str = node ? src.slice(range.start, node.range.start) + String(node) : src.slice(range.start, range.end);
        return PlainValue.Node.addStringTerminator(src, range.end, str);
      }
    };
    var Comment = class extends PlainValue.Node {
      constructor() {
        super(PlainValue.Type.COMMENT);
      }
      /**
       * Parses a comment line from the source
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this scalar
       */
      parse(context, start) {
        this.context = context;
        const offset = this.parseComment(start);
        this.range = new PlainValue.Range(start, offset);
        return offset;
      }
    };
    function grabCollectionEndComments(node) {
      let cnode = node;
      while (cnode instanceof CollectionItem)
        cnode = cnode.node;
      if (!(cnode instanceof Collection))
        return null;
      const len = cnode.items.length;
      let ci = -1;
      for (let i = len - 1; i >= 0; --i) {
        const n = cnode.items[i];
        if (n.type === PlainValue.Type.COMMENT) {
          const {
            indent,
            lineStart
          } = n.context;
          if (indent > 0 && n.range.start >= lineStart + indent)
            break;
          ci = i;
        } else if (n.type === PlainValue.Type.BLANK_LINE)
          ci = i;
        else
          break;
      }
      if (ci === -1)
        return null;
      const ca = cnode.items.splice(ci, len - ci);
      const prevEnd = ca[0].range.start;
      while (true) {
        cnode.range.end = prevEnd;
        if (cnode.valueRange && cnode.valueRange.end > prevEnd)
          cnode.valueRange.end = prevEnd;
        if (cnode === node)
          break;
        cnode = cnode.context.parent;
      }
      return ca;
    }
    var Collection = class _Collection extends PlainValue.Node {
      static nextContentHasIndent(src, offset, indent) {
        const lineStart = PlainValue.Node.endOfLine(src, offset) + 1;
        offset = PlainValue.Node.endOfWhiteSpace(src, lineStart);
        const ch = src[offset];
        if (!ch)
          return false;
        if (offset >= lineStart + indent)
          return true;
        if (ch !== "#" && ch !== "\n")
          return false;
        return _Collection.nextContentHasIndent(src, offset, indent);
      }
      constructor(firstItem) {
        super(firstItem.type === PlainValue.Type.SEQ_ITEM ? PlainValue.Type.SEQ : PlainValue.Type.MAP);
        for (let i = firstItem.props.length - 1; i >= 0; --i) {
          if (firstItem.props[i].start < firstItem.context.lineStart) {
            this.props = firstItem.props.slice(0, i + 1);
            firstItem.props = firstItem.props.slice(i + 1);
            const itemRange = firstItem.props[0] || firstItem.valueRange;
            firstItem.range.start = itemRange.start;
            break;
          }
        }
        this.items = [firstItem];
        const ec = grabCollectionEndComments(firstItem);
        if (ec)
          Array.prototype.push.apply(this.items, ec);
      }
      get includesTrailingLines() {
        return this.items.length > 0;
      }
      /**
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this
       */
      parse(context, start) {
        this.context = context;
        const {
          parseNode,
          src
        } = context;
        let lineStart = PlainValue.Node.startOfLine(src, start);
        const firstItem = this.items[0];
        firstItem.context.parent = this;
        this.valueRange = PlainValue.Range.copy(firstItem.valueRange);
        const indent = firstItem.range.start - firstItem.context.lineStart;
        let offset = start;
        offset = PlainValue.Node.normalizeOffset(src, offset);
        let ch = src[offset];
        let atLineStart = PlainValue.Node.endOfWhiteSpace(src, lineStart) === offset;
        let prevIncludesTrailingLines = false;
        while (ch) {
          while (ch === "\n" || ch === "#") {
            if (atLineStart && ch === "\n" && !prevIncludesTrailingLines) {
              const blankLine = new BlankLine();
              offset = blankLine.parse({
                src
              }, offset);
              this.valueRange.end = offset;
              if (offset >= src.length) {
                ch = null;
                break;
              }
              this.items.push(blankLine);
              offset -= 1;
            } else if (ch === "#") {
              if (offset < lineStart + indent && !_Collection.nextContentHasIndent(src, offset, indent)) {
                return offset;
              }
              const comment = new Comment();
              offset = comment.parse({
                indent,
                lineStart,
                src
              }, offset);
              this.items.push(comment);
              this.valueRange.end = offset;
              if (offset >= src.length) {
                ch = null;
                break;
              }
            }
            lineStart = offset + 1;
            offset = PlainValue.Node.endOfIndent(src, lineStart);
            if (PlainValue.Node.atBlank(src, offset)) {
              const wsEnd = PlainValue.Node.endOfWhiteSpace(src, offset);
              const next = src[wsEnd];
              if (!next || next === "\n" || next === "#") {
                offset = wsEnd;
              }
            }
            ch = src[offset];
            atLineStart = true;
          }
          if (!ch) {
            break;
          }
          if (offset !== lineStart + indent && (atLineStart || ch !== ":")) {
            if (offset < lineStart + indent) {
              if (lineStart > start)
                offset = lineStart;
              break;
            } else if (!this.error) {
              const msg = "All collection items must start at the same column";
              this.error = new PlainValue.YAMLSyntaxError(this, msg);
            }
          }
          if (firstItem.type === PlainValue.Type.SEQ_ITEM) {
            if (ch !== "-") {
              if (lineStart > start)
                offset = lineStart;
              break;
            }
          } else if (ch === "-" && !this.error) {
            const next = src[offset + 1];
            if (!next || next === "\n" || next === "	" || next === " ") {
              const msg = "A collection cannot be both a mapping and a sequence";
              this.error = new PlainValue.YAMLSyntaxError(this, msg);
            }
          }
          const node = parseNode({
            atLineStart,
            inCollection: true,
            indent,
            lineStart,
            parent: this
          }, offset);
          if (!node)
            return offset;
          this.items.push(node);
          this.valueRange.end = node.valueRange.end;
          offset = PlainValue.Node.normalizeOffset(src, node.range.end);
          ch = src[offset];
          atLineStart = false;
          prevIncludesTrailingLines = node.includesTrailingLines;
          if (ch) {
            let ls = offset - 1;
            let prev = src[ls];
            while (prev === " " || prev === "	")
              prev = src[--ls];
            if (prev === "\n") {
              lineStart = ls + 1;
              atLineStart = true;
            }
          }
          const ec = grabCollectionEndComments(node);
          if (ec)
            Array.prototype.push.apply(this.items, ec);
        }
        return offset;
      }
      setOrigRanges(cr, offset) {
        offset = super.setOrigRanges(cr, offset);
        this.items.forEach((node) => {
          offset = node.setOrigRanges(cr, offset);
        });
        return offset;
      }
      toString() {
        const {
          context: {
            src
          },
          items,
          range,
          value
        } = this;
        if (value != null)
          return value;
        let str = src.slice(range.start, items[0].range.start) + String(items[0]);
        for (let i = 1; i < items.length; ++i) {
          const item = items[i];
          const {
            atLineStart,
            indent
          } = item.context;
          if (atLineStart)
            for (let i2 = 0; i2 < indent; ++i2)
              str += " ";
          str += String(item);
        }
        return PlainValue.Node.addStringTerminator(src, range.end, str);
      }
    };
    var Directive = class extends PlainValue.Node {
      constructor() {
        super(PlainValue.Type.DIRECTIVE);
        this.name = null;
      }
      get parameters() {
        const raw = this.rawValue;
        return raw ? raw.trim().split(/[ \t]+/) : [];
      }
      parseName(start) {
        const {
          src
        } = this.context;
        let offset = start;
        let ch = src[offset];
        while (ch && ch !== "\n" && ch !== "	" && ch !== " ")
          ch = src[offset += 1];
        this.name = src.slice(start, offset);
        return offset;
      }
      parseParameters(start) {
        const {
          src
        } = this.context;
        let offset = start;
        let ch = src[offset];
        while (ch && ch !== "\n" && ch !== "#")
          ch = src[offset += 1];
        this.valueRange = new PlainValue.Range(start, offset);
        return offset;
      }
      parse(context, start) {
        this.context = context;
        let offset = this.parseName(start + 1);
        offset = this.parseParameters(offset);
        offset = this.parseComment(offset);
        this.range = new PlainValue.Range(start, offset);
        return offset;
      }
    };
    var Document = class _Document extends PlainValue.Node {
      static startCommentOrEndBlankLine(src, start) {
        const offset = PlainValue.Node.endOfWhiteSpace(src, start);
        const ch = src[offset];
        return ch === "#" || ch === "\n" ? offset : start;
      }
      constructor() {
        super(PlainValue.Type.DOCUMENT);
        this.directives = null;
        this.contents = null;
        this.directivesEndMarker = null;
        this.documentEndMarker = null;
      }
      parseDirectives(start) {
        const {
          src
        } = this.context;
        this.directives = [];
        let atLineStart = true;
        let hasDirectives = false;
        let offset = start;
        while (!PlainValue.Node.atDocumentBoundary(src, offset, PlainValue.Char.DIRECTIVES_END)) {
          offset = _Document.startCommentOrEndBlankLine(src, offset);
          switch (src[offset]) {
            case "\n":
              if (atLineStart) {
                const blankLine = new BlankLine();
                offset = blankLine.parse({
                  src
                }, offset);
                if (offset < src.length) {
                  this.directives.push(blankLine);
                }
              } else {
                offset += 1;
                atLineStart = true;
              }
              break;
            case "#":
              {
                const comment = new Comment();
                offset = comment.parse({
                  src
                }, offset);
                this.directives.push(comment);
                atLineStart = false;
              }
              break;
            case "%":
              {
                const directive = new Directive();
                offset = directive.parse({
                  parent: this,
                  src
                }, offset);
                this.directives.push(directive);
                hasDirectives = true;
                atLineStart = false;
              }
              break;
            default:
              if (hasDirectives) {
                this.error = new PlainValue.YAMLSemanticError(this, "Missing directives-end indicator line");
              } else if (this.directives.length > 0) {
                this.contents = this.directives;
                this.directives = [];
              }
              return offset;
          }
        }
        if (src[offset]) {
          this.directivesEndMarker = new PlainValue.Range(offset, offset + 3);
          return offset + 3;
        }
        if (hasDirectives) {
          this.error = new PlainValue.YAMLSemanticError(this, "Missing directives-end indicator line");
        } else if (this.directives.length > 0) {
          this.contents = this.directives;
          this.directives = [];
        }
        return offset;
      }
      parseContents(start) {
        const {
          parseNode,
          src
        } = this.context;
        if (!this.contents)
          this.contents = [];
        let lineStart = start;
        while (src[lineStart - 1] === "-")
          lineStart -= 1;
        let offset = PlainValue.Node.endOfWhiteSpace(src, start);
        let atLineStart = lineStart === start;
        this.valueRange = new PlainValue.Range(offset);
        while (!PlainValue.Node.atDocumentBoundary(src, offset, PlainValue.Char.DOCUMENT_END)) {
          switch (src[offset]) {
            case "\n":
              if (atLineStart) {
                const blankLine = new BlankLine();
                offset = blankLine.parse({
                  src
                }, offset);
                if (offset < src.length) {
                  this.contents.push(blankLine);
                }
              } else {
                offset += 1;
                atLineStart = true;
              }
              lineStart = offset;
              break;
            case "#":
              {
                const comment = new Comment();
                offset = comment.parse({
                  src
                }, offset);
                this.contents.push(comment);
                atLineStart = false;
              }
              break;
            default: {
              const iEnd = PlainValue.Node.endOfIndent(src, offset);
              const context = {
                atLineStart,
                indent: -1,
                inFlow: false,
                inCollection: false,
                lineStart,
                parent: this
              };
              const node = parseNode(context, iEnd);
              if (!node)
                return this.valueRange.end = iEnd;
              this.contents.push(node);
              offset = node.range.end;
              atLineStart = false;
              const ec = grabCollectionEndComments(node);
              if (ec)
                Array.prototype.push.apply(this.contents, ec);
            }
          }
          offset = _Document.startCommentOrEndBlankLine(src, offset);
        }
        this.valueRange.end = offset;
        if (src[offset]) {
          this.documentEndMarker = new PlainValue.Range(offset, offset + 3);
          offset += 3;
          if (src[offset]) {
            offset = PlainValue.Node.endOfWhiteSpace(src, offset);
            if (src[offset] === "#") {
              const comment = new Comment();
              offset = comment.parse({
                src
              }, offset);
              this.contents.push(comment);
            }
            switch (src[offset]) {
              case "\n":
                offset += 1;
                break;
              case void 0:
                break;
              default:
                this.error = new PlainValue.YAMLSyntaxError(this, "Document end marker line cannot have a non-comment suffix");
            }
          }
        }
        return offset;
      }
      /**
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this
       */
      parse(context, start) {
        context.root = this;
        this.context = context;
        const {
          src
        } = context;
        let offset = src.charCodeAt(start) === 65279 ? start + 1 : start;
        offset = this.parseDirectives(offset);
        offset = this.parseContents(offset);
        return offset;
      }
      setOrigRanges(cr, offset) {
        offset = super.setOrigRanges(cr, offset);
        this.directives.forEach((node) => {
          offset = node.setOrigRanges(cr, offset);
        });
        if (this.directivesEndMarker)
          offset = this.directivesEndMarker.setOrigRange(cr, offset);
        this.contents.forEach((node) => {
          offset = node.setOrigRanges(cr, offset);
        });
        if (this.documentEndMarker)
          offset = this.documentEndMarker.setOrigRange(cr, offset);
        return offset;
      }
      toString() {
        const {
          contents,
          directives,
          value
        } = this;
        if (value != null)
          return value;
        let str = directives.join("");
        if (contents.length > 0) {
          if (directives.length > 0 || contents[0].type === PlainValue.Type.COMMENT)
            str += "---\n";
          str += contents.join("");
        }
        if (str[str.length - 1] !== "\n")
          str += "\n";
        return str;
      }
    };
    var Alias = class extends PlainValue.Node {
      /**
       * Parses an *alias from the source
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this scalar
       */
      parse(context, start) {
        this.context = context;
        const {
          src
        } = context;
        let offset = PlainValue.Node.endOfIdentifier(src, start + 1);
        this.valueRange = new PlainValue.Range(start + 1, offset);
        offset = PlainValue.Node.endOfWhiteSpace(src, offset);
        offset = this.parseComment(offset);
        return offset;
      }
    };
    var Chomp = {
      CLIP: "CLIP",
      KEEP: "KEEP",
      STRIP: "STRIP"
    };
    var BlockValue = class extends PlainValue.Node {
      constructor(type, props) {
        super(type, props);
        this.blockIndent = null;
        this.chomping = Chomp.CLIP;
        this.header = null;
      }
      get includesTrailingLines() {
        return this.chomping === Chomp.KEEP;
      }
      get strValue() {
        if (!this.valueRange || !this.context)
          return null;
        let {
          start,
          end
        } = this.valueRange;
        const {
          indent,
          src
        } = this.context;
        if (this.valueRange.isEmpty())
          return "";
        let lastNewLine = null;
        let ch = src[end - 1];
        while (ch === "\n" || ch === "	" || ch === " ") {
          end -= 1;
          if (end <= start) {
            if (this.chomping === Chomp.KEEP)
              break;
            else
              return "";
          }
          if (ch === "\n")
            lastNewLine = end;
          ch = src[end - 1];
        }
        let keepStart = end + 1;
        if (lastNewLine) {
          if (this.chomping === Chomp.KEEP) {
            keepStart = lastNewLine;
            end = this.valueRange.end;
          } else {
            end = lastNewLine;
          }
        }
        const bi = indent + this.blockIndent;
        const folded = this.type === PlainValue.Type.BLOCK_FOLDED;
        let atStart = true;
        let str = "";
        let sep = "";
        let prevMoreIndented = false;
        for (let i = start; i < end; ++i) {
          for (let j = 0; j < bi; ++j) {
            if (src[i] !== " ")
              break;
            i += 1;
          }
          const ch2 = src[i];
          if (ch2 === "\n") {
            if (sep === "\n")
              str += "\n";
            else
              sep = "\n";
          } else {
            const lineEnd = PlainValue.Node.endOfLine(src, i);
            const line = src.slice(i, lineEnd);
            i = lineEnd;
            if (folded && (ch2 === " " || ch2 === "	") && i < keepStart) {
              if (sep === " ")
                sep = "\n";
              else if (!prevMoreIndented && !atStart && sep === "\n")
                sep = "\n\n";
              str += sep + line;
              sep = lineEnd < end && src[lineEnd] || "";
              prevMoreIndented = true;
            } else {
              str += sep + line;
              sep = folded && i < keepStart ? " " : "\n";
              prevMoreIndented = false;
            }
            if (atStart && line !== "")
              atStart = false;
          }
        }
        return this.chomping === Chomp.STRIP ? str : str + "\n";
      }
      parseBlockHeader(start) {
        const {
          src
        } = this.context;
        let offset = start + 1;
        let bi = "";
        while (true) {
          const ch = src[offset];
          switch (ch) {
            case "-":
              this.chomping = Chomp.STRIP;
              break;
            case "+":
              this.chomping = Chomp.KEEP;
              break;
            case "0":
            case "1":
            case "2":
            case "3":
            case "4":
            case "5":
            case "6":
            case "7":
            case "8":
            case "9":
              bi += ch;
              break;
            default:
              this.blockIndent = Number(bi) || null;
              this.header = new PlainValue.Range(start, offset);
              return offset;
          }
          offset += 1;
        }
      }
      parseBlockValue(start) {
        const {
          indent,
          src
        } = this.context;
        const explicit = !!this.blockIndent;
        let offset = start;
        let valueEnd = start;
        let minBlockIndent = 1;
        for (let ch = src[offset]; ch === "\n"; ch = src[offset]) {
          offset += 1;
          if (PlainValue.Node.atDocumentBoundary(src, offset))
            break;
          const end = PlainValue.Node.endOfBlockIndent(src, indent, offset);
          if (end === null)
            break;
          const ch2 = src[end];
          const lineIndent = end - (offset + indent);
          if (!this.blockIndent) {
            if (src[end] !== "\n") {
              if (lineIndent < minBlockIndent) {
                const msg = "Block scalars with more-indented leading empty lines must use an explicit indentation indicator";
                this.error = new PlainValue.YAMLSemanticError(this, msg);
              }
              this.blockIndent = lineIndent;
            } else if (lineIndent > minBlockIndent) {
              minBlockIndent = lineIndent;
            }
          } else if (ch2 && ch2 !== "\n" && lineIndent < this.blockIndent) {
            if (src[end] === "#")
              break;
            if (!this.error) {
              const src2 = explicit ? "explicit indentation indicator" : "first line";
              const msg = `Block scalars must not be less indented than their ${src2}`;
              this.error = new PlainValue.YAMLSemanticError(this, msg);
            }
          }
          if (src[end] === "\n") {
            offset = end;
          } else {
            offset = valueEnd = PlainValue.Node.endOfLine(src, end);
          }
        }
        if (this.chomping !== Chomp.KEEP) {
          offset = src[valueEnd] ? valueEnd + 1 : valueEnd;
        }
        this.valueRange = new PlainValue.Range(start + 1, offset);
        return offset;
      }
      /**
       * Parses a block value from the source
       *
       * Accepted forms are:
       * ```
       * BS
       * block
       * lines
       *
       * BS #comment
       * block
       * lines
       * ```
       * where the block style BS matches the regexp `[|>][-+1-9]*` and block lines
       * are empty or have an indent level greater than `indent`.
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this block
       */
      parse(context, start) {
        this.context = context;
        const {
          src
        } = context;
        let offset = this.parseBlockHeader(start);
        offset = PlainValue.Node.endOfWhiteSpace(src, offset);
        offset = this.parseComment(offset);
        offset = this.parseBlockValue(offset);
        return offset;
      }
      setOrigRanges(cr, offset) {
        offset = super.setOrigRanges(cr, offset);
        return this.header ? this.header.setOrigRange(cr, offset) : offset;
      }
    };
    var FlowCollection = class extends PlainValue.Node {
      constructor(type, props) {
        super(type, props);
        this.items = null;
      }
      prevNodeIsJsonLike(idx = this.items.length) {
        const node = this.items[idx - 1];
        return !!node && (node.jsonLike || node.type === PlainValue.Type.COMMENT && this.prevNodeIsJsonLike(idx - 1));
      }
      /**
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this
       */
      parse(context, start) {
        this.context = context;
        const {
          parseNode,
          src
        } = context;
        let {
          indent,
          lineStart
        } = context;
        let char = src[start];
        this.items = [{
          char,
          offset: start
        }];
        let offset = PlainValue.Node.endOfWhiteSpace(src, start + 1);
        char = src[offset];
        while (char && char !== "]" && char !== "}") {
          switch (char) {
            case "\n":
              {
                lineStart = offset + 1;
                const wsEnd = PlainValue.Node.endOfWhiteSpace(src, lineStart);
                if (src[wsEnd] === "\n") {
                  const blankLine = new BlankLine();
                  lineStart = blankLine.parse({
                    src
                  }, lineStart);
                  this.items.push(blankLine);
                }
                offset = PlainValue.Node.endOfIndent(src, lineStart);
                if (offset <= lineStart + indent) {
                  char = src[offset];
                  if (offset < lineStart + indent || char !== "]" && char !== "}") {
                    const msg = "Insufficient indentation in flow collection";
                    this.error = new PlainValue.YAMLSemanticError(this, msg);
                  }
                }
              }
              break;
            case ",":
              {
                this.items.push({
                  char,
                  offset
                });
                offset += 1;
              }
              break;
            case "#":
              {
                const comment = new Comment();
                offset = comment.parse({
                  src
                }, offset);
                this.items.push(comment);
              }
              break;
            case "?":
            case ":": {
              const next = src[offset + 1];
              if (next === "\n" || next === "	" || next === " " || next === "," || // in-flow : after JSON-like key does not need to be followed by whitespace
              char === ":" && this.prevNodeIsJsonLike()) {
                this.items.push({
                  char,
                  offset
                });
                offset += 1;
                break;
              }
            }
            default: {
              const node = parseNode({
                atLineStart: false,
                inCollection: false,
                inFlow: true,
                indent: -1,
                lineStart,
                parent: this
              }, offset);
              if (!node) {
                this.valueRange = new PlainValue.Range(start, offset);
                return offset;
              }
              this.items.push(node);
              offset = PlainValue.Node.normalizeOffset(src, node.range.end);
            }
          }
          offset = PlainValue.Node.endOfWhiteSpace(src, offset);
          char = src[offset];
        }
        this.valueRange = new PlainValue.Range(start, offset + 1);
        if (char) {
          this.items.push({
            char,
            offset
          });
          offset = PlainValue.Node.endOfWhiteSpace(src, offset + 1);
          offset = this.parseComment(offset);
        }
        return offset;
      }
      setOrigRanges(cr, offset) {
        offset = super.setOrigRanges(cr, offset);
        this.items.forEach((node) => {
          if (node instanceof PlainValue.Node) {
            offset = node.setOrigRanges(cr, offset);
          } else if (cr.length === 0) {
            node.origOffset = node.offset;
          } else {
            let i = offset;
            while (i < cr.length) {
              if (cr[i] > node.offset)
                break;
              else
                ++i;
            }
            node.origOffset = node.offset + i;
            offset = i;
          }
        });
        return offset;
      }
      toString() {
        const {
          context: {
            src
          },
          items,
          range,
          value
        } = this;
        if (value != null)
          return value;
        const nodes = items.filter((item) => item instanceof PlainValue.Node);
        let str = "";
        let prevEnd = range.start;
        nodes.forEach((node) => {
          const prefix = src.slice(prevEnd, node.range.start);
          prevEnd = node.range.end;
          str += prefix + String(node);
          if (str[str.length - 1] === "\n" && src[prevEnd - 1] !== "\n" && src[prevEnd] === "\n") {
            prevEnd += 1;
          }
        });
        str += src.slice(prevEnd, range.end);
        return PlainValue.Node.addStringTerminator(src, range.end, str);
      }
    };
    var QuoteDouble = class _QuoteDouble extends PlainValue.Node {
      static endOfQuote(src, offset) {
        let ch = src[offset];
        while (ch && ch !== '"') {
          offset += ch === "\\" ? 2 : 1;
          ch = src[offset];
        }
        return offset + 1;
      }
      /**
       * @returns {string | { str: string, errors: YAMLSyntaxError[] }}
       */
      get strValue() {
        if (!this.valueRange || !this.context)
          return null;
        const errors = [];
        const {
          start,
          end
        } = this.valueRange;
        const {
          indent,
          src
        } = this.context;
        if (src[end - 1] !== '"')
          errors.push(new PlainValue.YAMLSyntaxError(this, 'Missing closing "quote'));
        let str = "";
        for (let i = start + 1; i < end - 1; ++i) {
          const ch = src[i];
          if (ch === "\n") {
            if (PlainValue.Node.atDocumentBoundary(src, i + 1))
              errors.push(new PlainValue.YAMLSemanticError(this, "Document boundary indicators are not allowed within string values"));
            const {
              fold,
              offset,
              error
            } = PlainValue.Node.foldNewline(src, i, indent);
            str += fold;
            i = offset;
            if (error)
              errors.push(new PlainValue.YAMLSemanticError(this, "Multi-line double-quoted string needs to be sufficiently indented"));
          } else if (ch === "\\") {
            i += 1;
            switch (src[i]) {
              case "0":
                str += "\0";
                break;
              case "a":
                str += "\x07";
                break;
              case "b":
                str += "\b";
                break;
              case "e":
                str += "\x1B";
                break;
              case "f":
                str += "\f";
                break;
              case "n":
                str += "\n";
                break;
              case "r":
                str += "\r";
                break;
              case "t":
                str += "	";
                break;
              case "v":
                str += "\v";
                break;
              case "N":
                str += "\x85";
                break;
              case "_":
                str += "\xA0";
                break;
              case "L":
                str += "\u2028";
                break;
              case "P":
                str += "\u2029";
                break;
              case " ":
                str += " ";
                break;
              case '"':
                str += '"';
                break;
              case "/":
                str += "/";
                break;
              case "\\":
                str += "\\";
                break;
              case "	":
                str += "	";
                break;
              case "x":
                str += this.parseCharCode(i + 1, 2, errors);
                i += 2;
                break;
              case "u":
                str += this.parseCharCode(i + 1, 4, errors);
                i += 4;
                break;
              case "U":
                str += this.parseCharCode(i + 1, 8, errors);
                i += 8;
                break;
              case "\n":
                while (src[i + 1] === " " || src[i + 1] === "	")
                  i += 1;
                break;
              default:
                errors.push(new PlainValue.YAMLSyntaxError(this, `Invalid escape sequence ${src.substr(i - 1, 2)}`));
                str += "\\" + src[i];
            }
          } else if (ch === " " || ch === "	") {
            const wsStart = i;
            let next = src[i + 1];
            while (next === " " || next === "	") {
              i += 1;
              next = src[i + 1];
            }
            if (next !== "\n")
              str += i > wsStart ? src.slice(wsStart, i + 1) : ch;
          } else {
            str += ch;
          }
        }
        return errors.length > 0 ? {
          errors,
          str
        } : str;
      }
      parseCharCode(offset, length, errors) {
        const {
          src
        } = this.context;
        const cc = src.substr(offset, length);
        const ok = cc.length === length && /^[0-9a-fA-F]+$/.test(cc);
        const code = ok ? parseInt(cc, 16) : NaN;
        if (isNaN(code)) {
          errors.push(new PlainValue.YAMLSyntaxError(this, `Invalid escape sequence ${src.substr(offset - 2, length + 2)}`));
          return src.substr(offset - 2, length + 2);
        }
        return String.fromCodePoint(code);
      }
      /**
       * Parses a "double quoted" value from the source
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this scalar
       */
      parse(context, start) {
        this.context = context;
        const {
          src
        } = context;
        let offset = _QuoteDouble.endOfQuote(src, start + 1);
        this.valueRange = new PlainValue.Range(start, offset);
        offset = PlainValue.Node.endOfWhiteSpace(src, offset);
        offset = this.parseComment(offset);
        return offset;
      }
    };
    var QuoteSingle = class _QuoteSingle extends PlainValue.Node {
      static endOfQuote(src, offset) {
        let ch = src[offset];
        while (ch) {
          if (ch === "'") {
            if (src[offset + 1] !== "'")
              break;
            ch = src[offset += 2];
          } else {
            ch = src[offset += 1];
          }
        }
        return offset + 1;
      }
      /**
       * @returns {string | { str: string, errors: YAMLSyntaxError[] }}
       */
      get strValue() {
        if (!this.valueRange || !this.context)
          return null;
        const errors = [];
        const {
          start,
          end
        } = this.valueRange;
        const {
          indent,
          src
        } = this.context;
        if (src[end - 1] !== "'")
          errors.push(new PlainValue.YAMLSyntaxError(this, "Missing closing 'quote"));
        let str = "";
        for (let i = start + 1; i < end - 1; ++i) {
          const ch = src[i];
          if (ch === "\n") {
            if (PlainValue.Node.atDocumentBoundary(src, i + 1))
              errors.push(new PlainValue.YAMLSemanticError(this, "Document boundary indicators are not allowed within string values"));
            const {
              fold,
              offset,
              error
            } = PlainValue.Node.foldNewline(src, i, indent);
            str += fold;
            i = offset;
            if (error)
              errors.push(new PlainValue.YAMLSemanticError(this, "Multi-line single-quoted string needs to be sufficiently indented"));
          } else if (ch === "'") {
            str += ch;
            i += 1;
            if (src[i] !== "'")
              errors.push(new PlainValue.YAMLSyntaxError(this, "Unescaped single quote? This should not happen."));
          } else if (ch === " " || ch === "	") {
            const wsStart = i;
            let next = src[i + 1];
            while (next === " " || next === "	") {
              i += 1;
              next = src[i + 1];
            }
            if (next !== "\n")
              str += i > wsStart ? src.slice(wsStart, i + 1) : ch;
          } else {
            str += ch;
          }
        }
        return errors.length > 0 ? {
          errors,
          str
        } : str;
      }
      /**
       * Parses a 'single quoted' value from the source
       *
       * @param {ParseContext} context
       * @param {number} start - Index of first character
       * @returns {number} - Index of the character after this scalar
       */
      parse(context, start) {
        this.context = context;
        const {
          src
        } = context;
        let offset = _QuoteSingle.endOfQuote(src, start + 1);
        this.valueRange = new PlainValue.Range(start, offset);
        offset = PlainValue.Node.endOfWhiteSpace(src, offset);
        offset = this.parseComment(offset);
        return offset;
      }
    };
    function createNewNode(type, props) {
      switch (type) {
        case PlainValue.Type.ALIAS:
          return new Alias(type, props);
        case PlainValue.Type.BLOCK_FOLDED:
        case PlainValue.Type.BLOCK_LITERAL:
          return new BlockValue(type, props);
        case PlainValue.Type.FLOW_MAP:
        case PlainValue.Type.FLOW_SEQ:
          return new FlowCollection(type, props);
        case PlainValue.Type.MAP_KEY:
        case PlainValue.Type.MAP_VALUE:
        case PlainValue.Type.SEQ_ITEM:
          return new CollectionItem(type, props);
        case PlainValue.Type.COMMENT:
        case PlainValue.Type.PLAIN:
          return new PlainValue.PlainValue(type, props);
        case PlainValue.Type.QUOTE_DOUBLE:
          return new QuoteDouble(type, props);
        case PlainValue.Type.QUOTE_SINGLE:
          return new QuoteSingle(type, props);
        default:
          return null;
      }
    }
    var ParseContext = class _ParseContext {
      static parseType(src, offset, inFlow) {
        switch (src[offset]) {
          case "*":
            return PlainValue.Type.ALIAS;
          case ">":
            return PlainValue.Type.BLOCK_FOLDED;
          case "|":
            return PlainValue.Type.BLOCK_LITERAL;
          case "{":
            return PlainValue.Type.FLOW_MAP;
          case "[":
            return PlainValue.Type.FLOW_SEQ;
          case "?":
            return !inFlow && PlainValue.Node.atBlank(src, offset + 1, true) ? PlainValue.Type.MAP_KEY : PlainValue.Type.PLAIN;
          case ":":
            return !inFlow && PlainValue.Node.atBlank(src, offset + 1, true) ? PlainValue.Type.MAP_VALUE : PlainValue.Type.PLAIN;
          case "-":
            return !inFlow && PlainValue.Node.atBlank(src, offset + 1, true) ? PlainValue.Type.SEQ_ITEM : PlainValue.Type.PLAIN;
          case '"':
            return PlainValue.Type.QUOTE_DOUBLE;
          case "'":
            return PlainValue.Type.QUOTE_SINGLE;
          default:
            return PlainValue.Type.PLAIN;
        }
      }
      constructor(orig = {}, {
        atLineStart,
        inCollection,
        inFlow,
        indent,
        lineStart,
        parent
      } = {}) {
        PlainValue._defineProperty(this, "parseNode", (overlay, start) => {
          if (PlainValue.Node.atDocumentBoundary(this.src, start))
            return null;
          const context = new _ParseContext(this, overlay);
          const {
            props,
            type,
            valueStart
          } = context.parseProps(start);
          const node = createNewNode(type, props);
          let offset = start;
          try {
            offset = node.parse(context, valueStart);
          } catch (error) {
            const msg = error instanceof Error ? error.message : String(error);
            if (!node.error)
              node.error = new PlainValue.YAMLSyntaxError(node, msg);
          }
          node.range = new PlainValue.Range(start, offset);
          if (offset <= start) {
            if (!node.error)
              node.error = new Error(`Node#parse consumed no characters`);
            node.error.parseEnd = offset;
            node.error.source = node;
            node.range.end = start + 1;
          }
          if (context.nodeStartsCollection(node)) {
            if (!node.error && !context.atLineStart && context.parent.type === PlainValue.Type.DOCUMENT) {
              node.error = new PlainValue.YAMLSyntaxError(node, "Block collection must not have preceding content here (e.g. directives-end indicator)");
            }
            const collection = new Collection(node);
            offset = collection.parse(new _ParseContext(context), offset);
            collection.range = new PlainValue.Range(start, offset);
            return collection;
          }
          return node;
        });
        this.atLineStart = atLineStart != null ? atLineStart : orig.atLineStart || false;
        this.inCollection = inCollection != null ? inCollection : orig.inCollection || false;
        this.inFlow = inFlow != null ? inFlow : orig.inFlow || false;
        this.indent = indent != null ? indent : orig.indent;
        this.lineStart = lineStart != null ? lineStart : orig.lineStart;
        this.parent = parent != null ? parent : orig.parent || {};
        this.root = orig.root;
        this.src = orig.src;
      }
      nodeStartsCollection(node) {
        const {
          inCollection,
          inFlow,
          src
        } = this;
        if (inCollection || inFlow)
          return false;
        if (node instanceof CollectionItem)
          return true;
        let offset = node.range.end;
        if (src[offset] === "\n" || src[offset - 1] === "\n")
          return false;
        offset = PlainValue.Node.endOfWhiteSpace(src, offset);
        return src[offset] === ":";
      }
      // Anchor and tag are before type, which determines the node implementation
      // class; hence this intermediate step.
      parseProps(offset) {
        const {
          inFlow,
          parent,
          src
        } = this;
        const props = [];
        let lineHasProps = false;
        offset = this.atLineStart ? PlainValue.Node.endOfIndent(src, offset) : PlainValue.Node.endOfWhiteSpace(src, offset);
        let ch = src[offset];
        while (ch === PlainValue.Char.ANCHOR || ch === PlainValue.Char.COMMENT || ch === PlainValue.Char.TAG || ch === "\n") {
          if (ch === "\n") {
            let inEnd = offset;
            let lineStart;
            do {
              lineStart = inEnd + 1;
              inEnd = PlainValue.Node.endOfIndent(src, lineStart);
            } while (src[inEnd] === "\n");
            const indentDiff = inEnd - (lineStart + this.indent);
            const noIndicatorAsIndent = parent.type === PlainValue.Type.SEQ_ITEM && parent.context.atLineStart;
            if (src[inEnd] !== "#" && !PlainValue.Node.nextNodeIsIndented(src[inEnd], indentDiff, !noIndicatorAsIndent))
              break;
            this.atLineStart = true;
            this.lineStart = lineStart;
            lineHasProps = false;
            offset = inEnd;
          } else if (ch === PlainValue.Char.COMMENT) {
            const end = PlainValue.Node.endOfLine(src, offset + 1);
            props.push(new PlainValue.Range(offset, end));
            offset = end;
          } else {
            let end = PlainValue.Node.endOfIdentifier(src, offset + 1);
            if (ch === PlainValue.Char.TAG && src[end] === "," && /^[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+,\d\d\d\d(-\d\d){0,2}\/\S/.test(src.slice(offset + 1, end + 13))) {
              end = PlainValue.Node.endOfIdentifier(src, end + 5);
            }
            props.push(new PlainValue.Range(offset, end));
            lineHasProps = true;
            offset = PlainValue.Node.endOfWhiteSpace(src, end);
          }
          ch = src[offset];
        }
        if (lineHasProps && ch === ":" && PlainValue.Node.atBlank(src, offset + 1, true))
          offset -= 1;
        const type = _ParseContext.parseType(src, offset, inFlow);
        return {
          props,
          type,
          valueStart: offset
        };
      }
    };
    function parse(src) {
      const cr = [];
      if (src.indexOf("\r") !== -1) {
        src = src.replace(/\r\n?/g, (match, offset2) => {
          if (match.length > 1)
            cr.push(offset2);
          return "\n";
        });
      }
      const documents = [];
      let offset = 0;
      do {
        const doc = new Document();
        const context = new ParseContext({
          src
        });
        offset = doc.parse(context, offset);
        documents.push(doc);
      } while (offset < src.length);
      documents.setOrigRanges = () => {
        if (cr.length === 0)
          return false;
        for (let i = 1; i < cr.length; ++i)
          cr[i] -= i;
        let crOffset = 0;
        for (let i = 0; i < documents.length; ++i) {
          crOffset = documents[i].setOrigRanges(cr, crOffset);
        }
        cr.splice(0, cr.length);
        return true;
      };
      documents.toString = () => documents.join("...\n");
      return documents;
    }
    exports.parse = parse;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/resolveSeq-95613e94.js
var require_resolveSeq_95613e94 = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/resolveSeq-95613e94.js"(exports) {
    "use strict";
    var PlainValue = require_PlainValue_516d5bc2();
    function addCommentBefore(str, indent, comment) {
      if (!comment)
        return str;
      const cc = comment.replace(/[\s\S]^/gm, `$&${indent}#`);
      return `#${cc}
${indent}${str}`;
    }
    function addComment(str, indent, comment) {
      return !comment ? str : comment.indexOf("\n") === -1 ? `${str} #${comment}` : `${str}
` + comment.replace(/^/gm, `${indent || ""}#`);
    }
    var Node = class {
    };
    function toJSON(value, arg, ctx) {
      if (Array.isArray(value))
        return value.map((v, i) => toJSON(v, String(i), ctx));
      if (value && typeof value.toJSON === "function") {
        const anchor = ctx && ctx.anchors && ctx.anchors.get(value);
        if (anchor)
          ctx.onCreate = (res2) => {
            anchor.res = res2;
            delete ctx.onCreate;
          };
        const res = value.toJSON(arg, ctx);
        if (anchor && ctx.onCreate)
          ctx.onCreate(res);
        return res;
      }
      if ((!ctx || !ctx.keep) && typeof value === "bigint")
        return Number(value);
      return value;
    }
    var Scalar = class extends Node {
      constructor(value) {
        super();
        this.value = value;
      }
      toJSON(arg, ctx) {
        return ctx && ctx.keep ? this.value : toJSON(this.value, arg, ctx);
      }
      toString() {
        return String(this.value);
      }
    };
    function collectionFromPath(schema, path, value) {
      let v = value;
      for (let i = path.length - 1; i >= 0; --i) {
        const k = path[i];
        if (Number.isInteger(k) && k >= 0) {
          const a = [];
          a[k] = v;
          v = a;
        } else {
          const o = {};
          Object.defineProperty(o, k, {
            value: v,
            writable: true,
            enumerable: true,
            configurable: true
          });
          v = o;
        }
      }
      return schema.createNode(v, false);
    }
    var isEmptyPath = (path) => path == null || typeof path === "object" && path[Symbol.iterator]().next().done;
    var Collection = class _Collection extends Node {
      constructor(schema) {
        super();
        PlainValue._defineProperty(this, "items", []);
        this.schema = schema;
      }
      addIn(path, value) {
        if (isEmptyPath(path))
          this.add(value);
        else {
          const [key, ...rest] = path;
          const node = this.get(key, true);
          if (node instanceof _Collection)
            node.addIn(rest, value);
          else if (node === void 0 && this.schema)
            this.set(key, collectionFromPath(this.schema, rest, value));
          else
            throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
        }
      }
      deleteIn([key, ...rest]) {
        if (rest.length === 0)
          return this.delete(key);
        const node = this.get(key, true);
        if (node instanceof _Collection)
          return node.deleteIn(rest);
        else
          throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
      }
      getIn([key, ...rest], keepScalar) {
        const node = this.get(key, true);
        if (rest.length === 0)
          return !keepScalar && node instanceof Scalar ? node.value : node;
        else
          return node instanceof _Collection ? node.getIn(rest, keepScalar) : void 0;
      }
      hasAllNullValues() {
        return this.items.every((node) => {
          if (!node || node.type !== "PAIR")
            return false;
          const n = node.value;
          return n == null || n instanceof Scalar && n.value == null && !n.commentBefore && !n.comment && !n.tag;
        });
      }
      hasIn([key, ...rest]) {
        if (rest.length === 0)
          return this.has(key);
        const node = this.get(key, true);
        return node instanceof _Collection ? node.hasIn(rest) : false;
      }
      setIn([key, ...rest], value) {
        if (rest.length === 0) {
          this.set(key, value);
        } else {
          const node = this.get(key, true);
          if (node instanceof _Collection)
            node.setIn(rest, value);
          else if (node === void 0 && this.schema)
            this.set(key, collectionFromPath(this.schema, rest, value));
          else
            throw new Error(`Expected YAML collection at ${key}. Remaining path: ${rest}`);
        }
      }
      // overridden in implementations
      /* istanbul ignore next */
      toJSON() {
        return null;
      }
      toString(ctx, {
        blockItem,
        flowChars,
        isMap,
        itemIndent
      }, onComment, onChompKeep) {
        const {
          indent,
          indentStep,
          stringify
        } = ctx;
        const inFlow = this.type === PlainValue.Type.FLOW_MAP || this.type === PlainValue.Type.FLOW_SEQ || ctx.inFlow;
        if (inFlow)
          itemIndent += indentStep;
        const allNullValues = isMap && this.hasAllNullValues();
        ctx = Object.assign({}, ctx, {
          allNullValues,
          indent: itemIndent,
          inFlow,
          type: null
        });
        let chompKeep = false;
        let hasItemWithNewLine = false;
        const nodes = this.items.reduce((nodes2, item, i) => {
          let comment;
          if (item) {
            if (!chompKeep && item.spaceBefore)
              nodes2.push({
                type: "comment",
                str: ""
              });
            if (item.commentBefore)
              item.commentBefore.match(/^.*$/gm).forEach((line) => {
                nodes2.push({
                  type: "comment",
                  str: `#${line}`
                });
              });
            if (item.comment)
              comment = item.comment;
            if (inFlow && (!chompKeep && item.spaceBefore || item.commentBefore || item.comment || item.key && (item.key.commentBefore || item.key.comment) || item.value && (item.value.commentBefore || item.value.comment)))
              hasItemWithNewLine = true;
          }
          chompKeep = false;
          let str2 = stringify(item, ctx, () => comment = null, () => chompKeep = true);
          if (inFlow && !hasItemWithNewLine && str2.includes("\n"))
            hasItemWithNewLine = true;
          if (inFlow && i < this.items.length - 1)
            str2 += ",";
          str2 = addComment(str2, itemIndent, comment);
          if (chompKeep && (comment || inFlow))
            chompKeep = false;
          nodes2.push({
            type: "item",
            str: str2
          });
          return nodes2;
        }, []);
        let str;
        if (nodes.length === 0) {
          str = flowChars.start + flowChars.end;
        } else if (inFlow) {
          const {
            start,
            end
          } = flowChars;
          const strings = nodes.map((n) => n.str);
          if (hasItemWithNewLine || strings.reduce((sum, str2) => sum + str2.length + 2, 2) > _Collection.maxFlowStringSingleLineLength) {
            str = start;
            for (const s of strings) {
              str += s ? `
${indentStep}${indent}${s}` : "\n";
            }
            str += `
${indent}${end}`;
          } else {
            str = `${start} ${strings.join(" ")} ${end}`;
          }
        } else {
          const strings = nodes.map(blockItem);
          str = strings.shift();
          for (const s of strings)
            str += s ? `
${indent}${s}` : "\n";
        }
        if (this.comment) {
          str += "\n" + this.comment.replace(/^/gm, `${indent}#`);
          if (onComment)
            onComment();
        } else if (chompKeep && onChompKeep)
          onChompKeep();
        return str;
      }
    };
    PlainValue._defineProperty(Collection, "maxFlowStringSingleLineLength", 60);
    function asItemIndex(key) {
      let idx = key instanceof Scalar ? key.value : key;
      if (idx && typeof idx === "string")
        idx = Number(idx);
      return Number.isInteger(idx) && idx >= 0 ? idx : null;
    }
    var YAMLSeq = class extends Collection {
      add(value) {
        this.items.push(value);
      }
      delete(key) {
        const idx = asItemIndex(key);
        if (typeof idx !== "number")
          return false;
        const del = this.items.splice(idx, 1);
        return del.length > 0;
      }
      get(key, keepScalar) {
        const idx = asItemIndex(key);
        if (typeof idx !== "number")
          return void 0;
        const it = this.items[idx];
        return !keepScalar && it instanceof Scalar ? it.value : it;
      }
      has(key) {
        const idx = asItemIndex(key);
        return typeof idx === "number" && idx < this.items.length;
      }
      set(key, value) {
        const idx = asItemIndex(key);
        if (typeof idx !== "number")
          throw new Error(`Expected a valid index, not ${key}.`);
        this.items[idx] = value;
      }
      toJSON(_, ctx) {
        const seq = [];
        if (ctx && ctx.onCreate)
          ctx.onCreate(seq);
        let i = 0;
        for (const item of this.items)
          seq.push(toJSON(item, String(i++), ctx));
        return seq;
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx)
          return JSON.stringify(this);
        return super.toString(ctx, {
          blockItem: (n) => n.type === "comment" ? n.str : `- ${n.str}`,
          flowChars: {
            start: "[",
            end: "]"
          },
          isMap: false,
          itemIndent: (ctx.indent || "") + "  "
        }, onComment, onChompKeep);
      }
    };
    var stringifyKey = (key, jsKey, ctx) => {
      if (jsKey === null)
        return "";
      if (typeof jsKey !== "object")
        return String(jsKey);
      if (key instanceof Node && ctx && ctx.doc)
        return key.toString({
          anchors: /* @__PURE__ */ Object.create(null),
          doc: ctx.doc,
          indent: "",
          indentStep: ctx.indentStep,
          inFlow: true,
          inStringifyKey: true,
          stringify: ctx.stringify
        });
      return JSON.stringify(jsKey);
    };
    var Pair = class _Pair extends Node {
      constructor(key, value = null) {
        super();
        this.key = key;
        this.value = value;
        this.type = _Pair.Type.PAIR;
      }
      get commentBefore() {
        return this.key instanceof Node ? this.key.commentBefore : void 0;
      }
      set commentBefore(cb) {
        if (this.key == null)
          this.key = new Scalar(null);
        if (this.key instanceof Node)
          this.key.commentBefore = cb;
        else {
          const msg = "Pair.commentBefore is an alias for Pair.key.commentBefore. To set it, the key must be a Node.";
          throw new Error(msg);
        }
      }
      addToJSMap(ctx, map) {
        const key = toJSON(this.key, "", ctx);
        if (map instanceof Map) {
          const value = toJSON(this.value, key, ctx);
          map.set(key, value);
        } else if (map instanceof Set) {
          map.add(key);
        } else {
          const stringKey = stringifyKey(this.key, key, ctx);
          const value = toJSON(this.value, stringKey, ctx);
          if (stringKey in map)
            Object.defineProperty(map, stringKey, {
              value,
              writable: true,
              enumerable: true,
              configurable: true
            });
          else
            map[stringKey] = value;
        }
        return map;
      }
      toJSON(_, ctx) {
        const pair = ctx && ctx.mapAsMap ? /* @__PURE__ */ new Map() : {};
        return this.addToJSMap(ctx, pair);
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx || !ctx.doc)
          return JSON.stringify(this);
        const {
          indent: indentSize,
          indentSeq,
          simpleKeys
        } = ctx.doc.options;
        let {
          key,
          value
        } = this;
        let keyComment = key instanceof Node && key.comment;
        if (simpleKeys) {
          if (keyComment) {
            throw new Error("With simple keys, key nodes cannot have comments");
          }
          if (key instanceof Collection) {
            const msg = "With simple keys, collection cannot be used as a key value";
            throw new Error(msg);
          }
        }
        let explicitKey = !simpleKeys && (!key || keyComment || (key instanceof Node ? key instanceof Collection || key.type === PlainValue.Type.BLOCK_FOLDED || key.type === PlainValue.Type.BLOCK_LITERAL : typeof key === "object"));
        const {
          doc,
          indent,
          indentStep,
          stringify
        } = ctx;
        ctx = Object.assign({}, ctx, {
          implicitKey: !explicitKey,
          indent: indent + indentStep
        });
        let chompKeep = false;
        let str = stringify(key, ctx, () => keyComment = null, () => chompKeep = true);
        str = addComment(str, ctx.indent, keyComment);
        if (!explicitKey && str.length > 1024) {
          if (simpleKeys)
            throw new Error("With simple keys, single line scalar must not span more than 1024 characters");
          explicitKey = true;
        }
        if (ctx.allNullValues && !simpleKeys) {
          if (this.comment) {
            str = addComment(str, ctx.indent, this.comment);
            if (onComment)
              onComment();
          } else if (chompKeep && !keyComment && onChompKeep)
            onChompKeep();
          return ctx.inFlow && !explicitKey ? str : `? ${str}`;
        }
        str = explicitKey ? `? ${str}
${indent}:` : `${str}:`;
        if (this.comment) {
          str = addComment(str, ctx.indent, this.comment);
          if (onComment)
            onComment();
        }
        let vcb = "";
        let valueComment = null;
        if (value instanceof Node) {
          if (value.spaceBefore)
            vcb = "\n";
          if (value.commentBefore) {
            const cs = value.commentBefore.replace(/^/gm, `${ctx.indent}#`);
            vcb += `
${cs}`;
          }
          valueComment = value.comment;
        } else if (value && typeof value === "object") {
          value = doc.schema.createNode(value, true);
        }
        ctx.implicitKey = false;
        if (!explicitKey && !this.comment && value instanceof Scalar)
          ctx.indentAtStart = str.length + 1;
        chompKeep = false;
        if (!indentSeq && indentSize >= 2 && !ctx.inFlow && !explicitKey && value instanceof YAMLSeq && value.type !== PlainValue.Type.FLOW_SEQ && !value.tag && !doc.anchors.getName(value)) {
          ctx.indent = ctx.indent.substr(2);
        }
        const valueStr = stringify(value, ctx, () => valueComment = null, () => chompKeep = true);
        let ws = " ";
        if (vcb || this.comment) {
          ws = `${vcb}
${ctx.indent}`;
        } else if (!explicitKey && value instanceof Collection) {
          const flow = valueStr[0] === "[" || valueStr[0] === "{";
          if (!flow || valueStr.includes("\n"))
            ws = `
${ctx.indent}`;
        } else if (valueStr[0] === "\n")
          ws = "";
        if (chompKeep && !valueComment && onChompKeep)
          onChompKeep();
        return addComment(str + ws + valueStr, ctx.indent, valueComment);
      }
    };
    PlainValue._defineProperty(Pair, "Type", {
      PAIR: "PAIR",
      MERGE_PAIR: "MERGE_PAIR"
    });
    var getAliasCount = (node, anchors) => {
      if (node instanceof Alias) {
        const anchor = anchors.get(node.source);
        return anchor.count * anchor.aliasCount;
      } else if (node instanceof Collection) {
        let count = 0;
        for (const item of node.items) {
          const c = getAliasCount(item, anchors);
          if (c > count)
            count = c;
        }
        return count;
      } else if (node instanceof Pair) {
        const kc = getAliasCount(node.key, anchors);
        const vc = getAliasCount(node.value, anchors);
        return Math.max(kc, vc);
      }
      return 1;
    };
    var Alias = class _Alias extends Node {
      static stringify({
        range,
        source
      }, {
        anchors,
        doc,
        implicitKey,
        inStringifyKey
      }) {
        let anchor = Object.keys(anchors).find((a) => anchors[a] === source);
        if (!anchor && inStringifyKey)
          anchor = doc.anchors.getName(source) || doc.anchors.newName();
        if (anchor)
          return `*${anchor}${implicitKey ? " " : ""}`;
        const msg = doc.anchors.getName(source) ? "Alias node must be after source node" : "Source node not found for alias node";
        throw new Error(`${msg} [${range}]`);
      }
      constructor(source) {
        super();
        this.source = source;
        this.type = PlainValue.Type.ALIAS;
      }
      set tag(t) {
        throw new Error("Alias nodes cannot have tags");
      }
      toJSON(arg, ctx) {
        if (!ctx)
          return toJSON(this.source, arg, ctx);
        const {
          anchors,
          maxAliasCount
        } = ctx;
        const anchor = anchors.get(this.source);
        if (!anchor || anchor.res === void 0) {
          const msg = "This should not happen: Alias anchor was not resolved?";
          if (this.cstNode)
            throw new PlainValue.YAMLReferenceError(this.cstNode, msg);
          else
            throw new ReferenceError(msg);
        }
        if (maxAliasCount >= 0) {
          anchor.count += 1;
          if (anchor.aliasCount === 0)
            anchor.aliasCount = getAliasCount(this.source, anchors);
          if (anchor.count * anchor.aliasCount > maxAliasCount) {
            const msg = "Excessive alias count indicates a resource exhaustion attack";
            if (this.cstNode)
              throw new PlainValue.YAMLReferenceError(this.cstNode, msg);
            else
              throw new ReferenceError(msg);
          }
        }
        return anchor.res;
      }
      // Only called when stringifying an alias mapping key while constructing
      // Object output.
      toString(ctx) {
        return _Alias.stringify(this, ctx);
      }
    };
    PlainValue._defineProperty(Alias, "default", true);
    function findPair(items, key) {
      const k = key instanceof Scalar ? key.value : key;
      for (const it of items) {
        if (it instanceof Pair) {
          if (it.key === key || it.key === k)
            return it;
          if (it.key && it.key.value === k)
            return it;
        }
      }
      return void 0;
    }
    var YAMLMap = class extends Collection {
      add(pair, overwrite) {
        if (!pair)
          pair = new Pair(pair);
        else if (!(pair instanceof Pair))
          pair = new Pair(pair.key || pair, pair.value);
        const prev = findPair(this.items, pair.key);
        const sortEntries = this.schema && this.schema.sortMapEntries;
        if (prev) {
          if (overwrite)
            prev.value = pair.value;
          else
            throw new Error(`Key ${pair.key} already set`);
        } else if (sortEntries) {
          const i = this.items.findIndex((item) => sortEntries(pair, item) < 0);
          if (i === -1)
            this.items.push(pair);
          else
            this.items.splice(i, 0, pair);
        } else {
          this.items.push(pair);
        }
      }
      delete(key) {
        const it = findPair(this.items, key);
        if (!it)
          return false;
        const del = this.items.splice(this.items.indexOf(it), 1);
        return del.length > 0;
      }
      get(key, keepScalar) {
        const it = findPair(this.items, key);
        const node = it && it.value;
        return !keepScalar && node instanceof Scalar ? node.value : node;
      }
      has(key) {
        return !!findPair(this.items, key);
      }
      set(key, value) {
        this.add(new Pair(key, value), true);
      }
      /**
       * @param {*} arg ignored
       * @param {*} ctx Conversion context, originally set in Document#toJSON()
       * @param {Class} Type If set, forces the returned collection type
       * @returns {*} Instance of Type, Map, or Object
       */
      toJSON(_, ctx, Type) {
        const map = Type ? new Type() : ctx && ctx.mapAsMap ? /* @__PURE__ */ new Map() : {};
        if (ctx && ctx.onCreate)
          ctx.onCreate(map);
        for (const item of this.items)
          item.addToJSMap(ctx, map);
        return map;
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx)
          return JSON.stringify(this);
        for (const item of this.items) {
          if (!(item instanceof Pair))
            throw new Error(`Map items must all be pairs; found ${JSON.stringify(item)} instead`);
        }
        return super.toString(ctx, {
          blockItem: (n) => n.str,
          flowChars: {
            start: "{",
            end: "}"
          },
          isMap: true,
          itemIndent: ctx.indent || ""
        }, onComment, onChompKeep);
      }
    };
    var MERGE_KEY = "<<";
    var Merge = class extends Pair {
      constructor(pair) {
        if (pair instanceof Pair) {
          let seq = pair.value;
          if (!(seq instanceof YAMLSeq)) {
            seq = new YAMLSeq();
            seq.items.push(pair.value);
            seq.range = pair.value.range;
          }
          super(pair.key, seq);
          this.range = pair.range;
        } else {
          super(new Scalar(MERGE_KEY), new YAMLSeq());
        }
        this.type = Pair.Type.MERGE_PAIR;
      }
      // If the value associated with a merge key is a single mapping node, each of
      // its key/value pairs is inserted into the current mapping, unless the key
      // already exists in it. If the value associated with the merge key is a
      // sequence, then this sequence is expected to contain mapping nodes and each
      // of these nodes is merged in turn according to its order in the sequence.
      // Keys in mapping nodes earlier in the sequence override keys specified in
      // later mapping nodes. -- http://yaml.org/type/merge.html
      addToJSMap(ctx, map) {
        for (const {
          source
        } of this.value.items) {
          if (!(source instanceof YAMLMap))
            throw new Error("Merge sources must be maps");
          const srcMap = source.toJSON(null, ctx, Map);
          for (const [key, value] of srcMap) {
            if (map instanceof Map) {
              if (!map.has(key))
                map.set(key, value);
            } else if (map instanceof Set) {
              map.add(key);
            } else if (!Object.prototype.hasOwnProperty.call(map, key)) {
              Object.defineProperty(map, key, {
                value,
                writable: true,
                enumerable: true,
                configurable: true
              });
            }
          }
        }
        return map;
      }
      toString(ctx, onComment) {
        const seq = this.value;
        if (seq.items.length > 1)
          return super.toString(ctx, onComment);
        this.value = seq.items[0];
        const str = super.toString(ctx, onComment);
        this.value = seq;
        return str;
      }
    };
    var binaryOptions = {
      defaultType: PlainValue.Type.BLOCK_LITERAL,
      lineWidth: 76
    };
    var boolOptions = {
      trueStr: "true",
      falseStr: "false"
    };
    var intOptions = {
      asBigInt: false
    };
    var nullOptions = {
      nullStr: "null"
    };
    var strOptions = {
      defaultType: PlainValue.Type.PLAIN,
      doubleQuoted: {
        jsonEncoding: false,
        minMultiLineLength: 40
      },
      fold: {
        lineWidth: 80,
        minContentWidth: 20
      }
    };
    function resolveScalar(str, tags, scalarFallback) {
      for (const {
        format,
        test,
        resolve: resolve2
      } of tags) {
        if (test) {
          const match = str.match(test);
          if (match) {
            let res = resolve2.apply(null, match);
            if (!(res instanceof Scalar))
              res = new Scalar(res);
            if (format)
              res.format = format;
            return res;
          }
        }
      }
      if (scalarFallback)
        str = scalarFallback(str);
      return new Scalar(str);
    }
    var FOLD_FLOW = "flow";
    var FOLD_BLOCK = "block";
    var FOLD_QUOTED = "quoted";
    var consumeMoreIndentedLines = (text, i) => {
      let ch = text[i + 1];
      while (ch === " " || ch === "	") {
        do {
          ch = text[i += 1];
        } while (ch && ch !== "\n");
        ch = text[i + 1];
      }
      return i;
    };
    function foldFlowLines(text, indent, mode, {
      indentAtStart,
      lineWidth = 80,
      minContentWidth = 20,
      onFold,
      onOverflow
    }) {
      if (!lineWidth || lineWidth < 0)
        return text;
      const endStep = Math.max(1 + minContentWidth, 1 + lineWidth - indent.length);
      if (text.length <= endStep)
        return text;
      const folds = [];
      const escapedFolds = {};
      let end = lineWidth - indent.length;
      if (typeof indentAtStart === "number") {
        if (indentAtStart > lineWidth - Math.max(2, minContentWidth))
          folds.push(0);
        else
          end = lineWidth - indentAtStart;
      }
      let split = void 0;
      let prev = void 0;
      let overflow = false;
      let i = -1;
      let escStart = -1;
      let escEnd = -1;
      if (mode === FOLD_BLOCK) {
        i = consumeMoreIndentedLines(text, i);
        if (i !== -1)
          end = i + endStep;
      }
      for (let ch; ch = text[i += 1]; ) {
        if (mode === FOLD_QUOTED && ch === "\\") {
          escStart = i;
          switch (text[i + 1]) {
            case "x":
              i += 3;
              break;
            case "u":
              i += 5;
              break;
            case "U":
              i += 9;
              break;
            default:
              i += 1;
          }
          escEnd = i;
        }
        if (ch === "\n") {
          if (mode === FOLD_BLOCK)
            i = consumeMoreIndentedLines(text, i);
          end = i + endStep;
          split = void 0;
        } else {
          if (ch === " " && prev && prev !== " " && prev !== "\n" && prev !== "	") {
            const next = text[i + 1];
            if (next && next !== " " && next !== "\n" && next !== "	")
              split = i;
          }
          if (i >= end) {
            if (split) {
              folds.push(split);
              end = split + endStep;
              split = void 0;
            } else if (mode === FOLD_QUOTED) {
              while (prev === " " || prev === "	") {
                prev = ch;
                ch = text[i += 1];
                overflow = true;
              }
              const j = i > escEnd + 1 ? i - 2 : escStart - 1;
              if (escapedFolds[j])
                return text;
              folds.push(j);
              escapedFolds[j] = true;
              end = j + endStep;
              split = void 0;
            } else {
              overflow = true;
            }
          }
        }
        prev = ch;
      }
      if (overflow && onOverflow)
        onOverflow();
      if (folds.length === 0)
        return text;
      if (onFold)
        onFold();
      let res = text.slice(0, folds[0]);
      for (let i2 = 0; i2 < folds.length; ++i2) {
        const fold = folds[i2];
        const end2 = folds[i2 + 1] || text.length;
        if (fold === 0)
          res = `
${indent}${text.slice(0, end2)}`;
        else {
          if (mode === FOLD_QUOTED && escapedFolds[fold])
            res += `${text[fold]}\\`;
          res += `
${indent}${text.slice(fold + 1, end2)}`;
        }
      }
      return res;
    }
    var getFoldOptions = ({
      indentAtStart
    }) => indentAtStart ? Object.assign({
      indentAtStart
    }, strOptions.fold) : strOptions.fold;
    var containsDocumentMarker = (str) => /^(%|---|\.\.\.)/m.test(str);
    function lineLengthOverLimit(str, lineWidth, indentLength) {
      if (!lineWidth || lineWidth < 0)
        return false;
      const limit = lineWidth - indentLength;
      const strLen = str.length;
      if (strLen <= limit)
        return false;
      for (let i = 0, start = 0; i < strLen; ++i) {
        if (str[i] === "\n") {
          if (i - start > limit)
            return true;
          start = i + 1;
          if (strLen - start <= limit)
            return false;
        }
      }
      return true;
    }
    function doubleQuotedString(value, ctx) {
      const {
        implicitKey
      } = ctx;
      const {
        jsonEncoding,
        minMultiLineLength
      } = strOptions.doubleQuoted;
      const json = JSON.stringify(value);
      if (jsonEncoding)
        return json;
      const indent = ctx.indent || (containsDocumentMarker(value) ? "  " : "");
      let str = "";
      let start = 0;
      for (let i = 0, ch = json[i]; ch; ch = json[++i]) {
        if (ch === " " && json[i + 1] === "\\" && json[i + 2] === "n") {
          str += json.slice(start, i) + "\\ ";
          i += 1;
          start = i;
          ch = "\\";
        }
        if (ch === "\\")
          switch (json[i + 1]) {
            case "u":
              {
                str += json.slice(start, i);
                const code = json.substr(i + 2, 4);
                switch (code) {
                  case "0000":
                    str += "\\0";
                    break;
                  case "0007":
                    str += "\\a";
                    break;
                  case "000b":
                    str += "\\v";
                    break;
                  case "001b":
                    str += "\\e";
                    break;
                  case "0085":
                    str += "\\N";
                    break;
                  case "00a0":
                    str += "\\_";
                    break;
                  case "2028":
                    str += "\\L";
                    break;
                  case "2029":
                    str += "\\P";
                    break;
                  default:
                    if (code.substr(0, 2) === "00")
                      str += "\\x" + code.substr(2);
                    else
                      str += json.substr(i, 6);
                }
                i += 5;
                start = i + 1;
              }
              break;
            case "n":
              if (implicitKey || json[i + 2] === '"' || json.length < minMultiLineLength) {
                i += 1;
              } else {
                str += json.slice(start, i) + "\n\n";
                while (json[i + 2] === "\\" && json[i + 3] === "n" && json[i + 4] !== '"') {
                  str += "\n";
                  i += 2;
                }
                str += indent;
                if (json[i + 2] === " ")
                  str += "\\";
                i += 1;
                start = i + 1;
              }
              break;
            default:
              i += 1;
          }
      }
      str = start ? str + json.slice(start) : json;
      return implicitKey ? str : foldFlowLines(str, indent, FOLD_QUOTED, getFoldOptions(ctx));
    }
    function singleQuotedString(value, ctx) {
      if (ctx.implicitKey) {
        if (/\n/.test(value))
          return doubleQuotedString(value, ctx);
      } else {
        if (/[ \t]\n|\n[ \t]/.test(value))
          return doubleQuotedString(value, ctx);
      }
      const indent = ctx.indent || (containsDocumentMarker(value) ? "  " : "");
      const res = "'" + value.replace(/'/g, "''").replace(/\n+/g, `$&
${indent}`) + "'";
      return ctx.implicitKey ? res : foldFlowLines(res, indent, FOLD_FLOW, getFoldOptions(ctx));
    }
    function blockString({
      comment,
      type,
      value
    }, ctx, onComment, onChompKeep) {
      if (/\n[\t ]+$/.test(value) || /^\s*$/.test(value)) {
        return doubleQuotedString(value, ctx);
      }
      const indent = ctx.indent || (ctx.forceBlockIndent || containsDocumentMarker(value) ? "  " : "");
      const indentSize = indent ? "2" : "1";
      const literal = type === PlainValue.Type.BLOCK_FOLDED ? false : type === PlainValue.Type.BLOCK_LITERAL ? true : !lineLengthOverLimit(value, strOptions.fold.lineWidth, indent.length);
      let header = literal ? "|" : ">";
      if (!value)
        return header + "\n";
      let wsStart = "";
      let wsEnd = "";
      value = value.replace(/[\n\t ]*$/, (ws) => {
        const n = ws.indexOf("\n");
        if (n === -1) {
          header += "-";
        } else if (value === ws || n !== ws.length - 1) {
          header += "+";
          if (onChompKeep)
            onChompKeep();
        }
        wsEnd = ws.replace(/\n$/, "");
        return "";
      }).replace(/^[\n ]*/, (ws) => {
        if (ws.indexOf(" ") !== -1)
          header += indentSize;
        const m = ws.match(/ +$/);
        if (m) {
          wsStart = ws.slice(0, -m[0].length);
          return m[0];
        } else {
          wsStart = ws;
          return "";
        }
      });
      if (wsEnd)
        wsEnd = wsEnd.replace(/\n+(?!\n|$)/g, `$&${indent}`);
      if (wsStart)
        wsStart = wsStart.replace(/\n+/g, `$&${indent}`);
      if (comment) {
        header += " #" + comment.replace(/ ?[\r\n]+/g, " ");
        if (onComment)
          onComment();
      }
      if (!value)
        return `${header}${indentSize}
${indent}${wsEnd}`;
      if (literal) {
        value = value.replace(/\n+/g, `$&${indent}`);
        return `${header}
${indent}${wsStart}${value}${wsEnd}`;
      }
      value = value.replace(/\n+/g, "\n$&").replace(/(?:^|\n)([\t ].*)(?:([\n\t ]*)\n(?![\n\t ]))?/g, "$1$2").replace(/\n+/g, `$&${indent}`);
      const body = foldFlowLines(`${wsStart}${value}${wsEnd}`, indent, FOLD_BLOCK, strOptions.fold);
      return `${header}
${indent}${body}`;
    }
    function plainString(item, ctx, onComment, onChompKeep) {
      const {
        comment,
        type,
        value
      } = item;
      const {
        actualString,
        implicitKey,
        indent,
        inFlow
      } = ctx;
      if (implicitKey && /[\n[\]{},]/.test(value) || inFlow && /[[\]{},]/.test(value)) {
        return doubleQuotedString(value, ctx);
      }
      if (!value || /^[\n\t ,[\]{}#&*!|>'"%@`]|^[?-]$|^[?-][ \t]|[\n:][ \t]|[ \t]\n|[\n\t ]#|[\n\t :]$/.test(value)) {
        return implicitKey || inFlow || value.indexOf("\n") === -1 ? value.indexOf('"') !== -1 && value.indexOf("'") === -1 ? singleQuotedString(value, ctx) : doubleQuotedString(value, ctx) : blockString(item, ctx, onComment, onChompKeep);
      }
      if (!implicitKey && !inFlow && type !== PlainValue.Type.PLAIN && value.indexOf("\n") !== -1) {
        return blockString(item, ctx, onComment, onChompKeep);
      }
      if (indent === "" && containsDocumentMarker(value)) {
        ctx.forceBlockIndent = true;
        return blockString(item, ctx, onComment, onChompKeep);
      }
      const str = value.replace(/\n+/g, `$&
${indent}`);
      if (actualString) {
        const {
          tags
        } = ctx.doc.schema;
        const resolved = resolveScalar(str, tags, tags.scalarFallback).value;
        if (typeof resolved !== "string")
          return doubleQuotedString(value, ctx);
      }
      const body = implicitKey ? str : foldFlowLines(str, indent, FOLD_FLOW, getFoldOptions(ctx));
      if (comment && !inFlow && (body.indexOf("\n") !== -1 || comment.indexOf("\n") !== -1)) {
        if (onComment)
          onComment();
        return addCommentBefore(body, indent, comment);
      }
      return body;
    }
    function stringifyString(item, ctx, onComment, onChompKeep) {
      const {
        defaultType
      } = strOptions;
      const {
        implicitKey,
        inFlow
      } = ctx;
      let {
        type,
        value
      } = item;
      if (typeof value !== "string") {
        value = String(value);
        item = Object.assign({}, item, {
          value
        });
      }
      const _stringify = (_type) => {
        switch (_type) {
          case PlainValue.Type.BLOCK_FOLDED:
          case PlainValue.Type.BLOCK_LITERAL:
            return blockString(item, ctx, onComment, onChompKeep);
          case PlainValue.Type.QUOTE_DOUBLE:
            return doubleQuotedString(value, ctx);
          case PlainValue.Type.QUOTE_SINGLE:
            return singleQuotedString(value, ctx);
          case PlainValue.Type.PLAIN:
            return plainString(item, ctx, onComment, onChompKeep);
          default:
            return null;
        }
      };
      if (type !== PlainValue.Type.QUOTE_DOUBLE && /[\x00-\x08\x0b-\x1f\x7f-\x9f]/.test(value)) {
        type = PlainValue.Type.QUOTE_DOUBLE;
      } else if ((implicitKey || inFlow) && (type === PlainValue.Type.BLOCK_FOLDED || type === PlainValue.Type.BLOCK_LITERAL)) {
        type = PlainValue.Type.QUOTE_DOUBLE;
      }
      let res = _stringify(type);
      if (res === null) {
        res = _stringify(defaultType);
        if (res === null)
          throw new Error(`Unsupported default string type ${defaultType}`);
      }
      return res;
    }
    function stringifyNumber({
      format,
      minFractionDigits,
      tag,
      value
    }) {
      if (typeof value === "bigint")
        return String(value);
      if (!isFinite(value))
        return isNaN(value) ? ".nan" : value < 0 ? "-.inf" : ".inf";
      let n = JSON.stringify(value);
      if (!format && minFractionDigits && (!tag || tag === "tag:yaml.org,2002:float") && /^\d/.test(n)) {
        let i = n.indexOf(".");
        if (i < 0) {
          i = n.length;
          n += ".";
        }
        let d = minFractionDigits - (n.length - i - 1);
        while (d-- > 0)
          n += "0";
      }
      return n;
    }
    function checkFlowCollectionEnd(errors, cst) {
      let char, name;
      switch (cst.type) {
        case PlainValue.Type.FLOW_MAP:
          char = "}";
          name = "flow map";
          break;
        case PlainValue.Type.FLOW_SEQ:
          char = "]";
          name = "flow sequence";
          break;
        default:
          errors.push(new PlainValue.YAMLSemanticError(cst, "Not a flow collection!?"));
          return;
      }
      let lastItem;
      for (let i = cst.items.length - 1; i >= 0; --i) {
        const item = cst.items[i];
        if (!item || item.type !== PlainValue.Type.COMMENT) {
          lastItem = item;
          break;
        }
      }
      if (lastItem && lastItem.char !== char) {
        const msg = `Expected ${name} to end with ${char}`;
        let err;
        if (typeof lastItem.offset === "number") {
          err = new PlainValue.YAMLSemanticError(cst, msg);
          err.offset = lastItem.offset + 1;
        } else {
          err = new PlainValue.YAMLSemanticError(lastItem, msg);
          if (lastItem.range && lastItem.range.end)
            err.offset = lastItem.range.end - lastItem.range.start;
        }
        errors.push(err);
      }
    }
    function checkFlowCommentSpace(errors, comment) {
      const prev = comment.context.src[comment.range.start - 1];
      if (prev !== "\n" && prev !== "	" && prev !== " ") {
        const msg = "Comments must be separated from other tokens by white space characters";
        errors.push(new PlainValue.YAMLSemanticError(comment, msg));
      }
    }
    function getLongKeyError(source, key) {
      const sk = String(key);
      const k = sk.substr(0, 8) + "..." + sk.substr(-8);
      return new PlainValue.YAMLSemanticError(source, `The "${k}" key is too long`);
    }
    function resolveComments(collection, comments) {
      for (const {
        afterKey,
        before,
        comment
      } of comments) {
        let item = collection.items[before];
        if (!item) {
          if (comment !== void 0) {
            if (collection.comment)
              collection.comment += "\n" + comment;
            else
              collection.comment = comment;
          }
        } else {
          if (afterKey && item.value)
            item = item.value;
          if (comment === void 0) {
            if (afterKey || !item.commentBefore)
              item.spaceBefore = true;
          } else {
            if (item.commentBefore)
              item.commentBefore += "\n" + comment;
            else
              item.commentBefore = comment;
          }
        }
      }
    }
    function resolveString(doc, node) {
      const res = node.strValue;
      if (!res)
        return "";
      if (typeof res === "string")
        return res;
      res.errors.forEach((error) => {
        if (!error.source)
          error.source = node;
        doc.errors.push(error);
      });
      return res.str;
    }
    function resolveTagHandle(doc, node) {
      const {
        handle,
        suffix
      } = node.tag;
      let prefix = doc.tagPrefixes.find((p) => p.handle === handle);
      if (!prefix) {
        const dtp = doc.getDefaults().tagPrefixes;
        if (dtp)
          prefix = dtp.find((p) => p.handle === handle);
        if (!prefix)
          throw new PlainValue.YAMLSemanticError(node, `The ${handle} tag handle is non-default and was not declared.`);
      }
      if (!suffix)
        throw new PlainValue.YAMLSemanticError(node, `The ${handle} tag has no suffix.`);
      if (handle === "!" && (doc.version || doc.options.version) === "1.0") {
        if (suffix[0] === "^") {
          doc.warnings.push(new PlainValue.YAMLWarning(node, "YAML 1.0 ^ tag expansion is not supported"));
          return suffix;
        }
        if (/[:/]/.test(suffix)) {
          const vocab = suffix.match(/^([a-z0-9-]+)\/(.*)/i);
          return vocab ? `tag:${vocab[1]}.yaml.org,2002:${vocab[2]}` : `tag:${suffix}`;
        }
      }
      return prefix.prefix + decodeURIComponent(suffix);
    }
    function resolveTagName(doc, node) {
      const {
        tag,
        type
      } = node;
      let nonSpecific = false;
      if (tag) {
        const {
          handle,
          suffix,
          verbatim
        } = tag;
        if (verbatim) {
          if (verbatim !== "!" && verbatim !== "!!")
            return verbatim;
          const msg = `Verbatim tags aren't resolved, so ${verbatim} is invalid.`;
          doc.errors.push(new PlainValue.YAMLSemanticError(node, msg));
        } else if (handle === "!" && !suffix) {
          nonSpecific = true;
        } else {
          try {
            return resolveTagHandle(doc, node);
          } catch (error) {
            doc.errors.push(error);
          }
        }
      }
      switch (type) {
        case PlainValue.Type.BLOCK_FOLDED:
        case PlainValue.Type.BLOCK_LITERAL:
        case PlainValue.Type.QUOTE_DOUBLE:
        case PlainValue.Type.QUOTE_SINGLE:
          return PlainValue.defaultTags.STR;
        case PlainValue.Type.FLOW_MAP:
        case PlainValue.Type.MAP:
          return PlainValue.defaultTags.MAP;
        case PlainValue.Type.FLOW_SEQ:
        case PlainValue.Type.SEQ:
          return PlainValue.defaultTags.SEQ;
        case PlainValue.Type.PLAIN:
          return nonSpecific ? PlainValue.defaultTags.STR : null;
        default:
          return null;
      }
    }
    function resolveByTagName(doc, node, tagName) {
      const {
        tags
      } = doc.schema;
      const matchWithTest = [];
      for (const tag of tags) {
        if (tag.tag === tagName) {
          if (tag.test)
            matchWithTest.push(tag);
          else {
            const res = tag.resolve(doc, node);
            return res instanceof Collection ? res : new Scalar(res);
          }
        }
      }
      const str = resolveString(doc, node);
      if (typeof str === "string" && matchWithTest.length > 0)
        return resolveScalar(str, matchWithTest, tags.scalarFallback);
      return null;
    }
    function getFallbackTagName({
      type
    }) {
      switch (type) {
        case PlainValue.Type.FLOW_MAP:
        case PlainValue.Type.MAP:
          return PlainValue.defaultTags.MAP;
        case PlainValue.Type.FLOW_SEQ:
        case PlainValue.Type.SEQ:
          return PlainValue.defaultTags.SEQ;
        default:
          return PlainValue.defaultTags.STR;
      }
    }
    function resolveTag(doc, node, tagName) {
      try {
        const res = resolveByTagName(doc, node, tagName);
        if (res) {
          if (tagName && node.tag)
            res.tag = tagName;
          return res;
        }
      } catch (error) {
        if (error instanceof PlainValue.YAMLError) {
          if (!error.source)
            error.source = node;
          doc.errors.push(error);
        } else {
          const msg = error instanceof Error ? error.message : String(error);
          doc.errors.push(new PlainValue.YAMLSemanticError(node, msg));
        }
        return null;
      }
      try {
        const fallback = getFallbackTagName(node);
        if (!fallback)
          throw new Error(`The tag ${tagName} is unavailable`);
        const msg = `The tag ${tagName} is unavailable, falling back to ${fallback}`;
        doc.warnings.push(new PlainValue.YAMLWarning(node, msg));
        const res = resolveByTagName(doc, node, fallback);
        res.tag = tagName;
        return res;
      } catch (error) {
        const refError = new PlainValue.YAMLReferenceError(node, error.message);
        refError.stack = error.stack;
        doc.errors.push(refError);
        return null;
      }
    }
    var isCollectionItem = (node) => {
      if (!node)
        return false;
      const {
        type
      } = node;
      return type === PlainValue.Type.MAP_KEY || type === PlainValue.Type.MAP_VALUE || type === PlainValue.Type.SEQ_ITEM;
    };
    function resolveNodeProps(errors, node) {
      const comments = {
        before: [],
        after: []
      };
      let hasAnchor = false;
      let hasTag = false;
      const props = isCollectionItem(node.context.parent) ? node.context.parent.props.concat(node.props) : node.props;
      for (const {
        start,
        end
      } of props) {
        switch (node.context.src[start]) {
          case PlainValue.Char.COMMENT: {
            if (!node.commentHasRequiredWhitespace(start)) {
              const msg = "Comments must be separated from other tokens by white space characters";
              errors.push(new PlainValue.YAMLSemanticError(node, msg));
            }
            const {
              header,
              valueRange
            } = node;
            const cc = valueRange && (start > valueRange.start || header && start > header.start) ? comments.after : comments.before;
            cc.push(node.context.src.slice(start + 1, end));
            break;
          }
          case PlainValue.Char.ANCHOR:
            if (hasAnchor) {
              const msg = "A node can have at most one anchor";
              errors.push(new PlainValue.YAMLSemanticError(node, msg));
            }
            hasAnchor = true;
            break;
          case PlainValue.Char.TAG:
            if (hasTag) {
              const msg = "A node can have at most one tag";
              errors.push(new PlainValue.YAMLSemanticError(node, msg));
            }
            hasTag = true;
            break;
        }
      }
      return {
        comments,
        hasAnchor,
        hasTag
      };
    }
    function resolveNodeValue(doc, node) {
      const {
        anchors,
        errors,
        schema
      } = doc;
      if (node.type === PlainValue.Type.ALIAS) {
        const name = node.rawValue;
        const src = anchors.getNode(name);
        if (!src) {
          const msg = `Aliased anchor not found: ${name}`;
          errors.push(new PlainValue.YAMLReferenceError(node, msg));
          return null;
        }
        const res = new Alias(src);
        anchors._cstAliases.push(res);
        return res;
      }
      const tagName = resolveTagName(doc, node);
      if (tagName)
        return resolveTag(doc, node, tagName);
      if (node.type !== PlainValue.Type.PLAIN) {
        const msg = `Failed to resolve ${node.type} node here`;
        errors.push(new PlainValue.YAMLSyntaxError(node, msg));
        return null;
      }
      try {
        const str = resolveString(doc, node);
        return resolveScalar(str, schema.tags, schema.tags.scalarFallback);
      } catch (error) {
        if (!error.source)
          error.source = node;
        errors.push(error);
        return null;
      }
    }
    function resolveNode(doc, node) {
      if (!node)
        return null;
      if (node.error)
        doc.errors.push(node.error);
      const {
        comments,
        hasAnchor,
        hasTag
      } = resolveNodeProps(doc.errors, node);
      if (hasAnchor) {
        const {
          anchors
        } = doc;
        const name = node.anchor;
        const prev = anchors.getNode(name);
        if (prev)
          anchors.map[anchors.newName(name)] = prev;
        anchors.map[name] = node;
      }
      if (node.type === PlainValue.Type.ALIAS && (hasAnchor || hasTag)) {
        const msg = "An alias node must not specify any properties";
        doc.errors.push(new PlainValue.YAMLSemanticError(node, msg));
      }
      const res = resolveNodeValue(doc, node);
      if (res) {
        res.range = [node.range.start, node.range.end];
        if (doc.options.keepCstNodes)
          res.cstNode = node;
        if (doc.options.keepNodeTypes)
          res.type = node.type;
        const cb = comments.before.join("\n");
        if (cb) {
          res.commentBefore = res.commentBefore ? `${res.commentBefore}
${cb}` : cb;
        }
        const ca = comments.after.join("\n");
        if (ca)
          res.comment = res.comment ? `${res.comment}
${ca}` : ca;
      }
      return node.resolved = res;
    }
    function resolveMap(doc, cst) {
      if (cst.type !== PlainValue.Type.MAP && cst.type !== PlainValue.Type.FLOW_MAP) {
        const msg = `A ${cst.type} node cannot be resolved as a mapping`;
        doc.errors.push(new PlainValue.YAMLSyntaxError(cst, msg));
        return null;
      }
      const {
        comments,
        items
      } = cst.type === PlainValue.Type.FLOW_MAP ? resolveFlowMapItems(doc, cst) : resolveBlockMapItems(doc, cst);
      const map = new YAMLMap();
      map.items = items;
      resolveComments(map, comments);
      let hasCollectionKey = false;
      for (let i = 0; i < items.length; ++i) {
        const {
          key: iKey
        } = items[i];
        if (iKey instanceof Collection)
          hasCollectionKey = true;
        if (doc.schema.merge && iKey && iKey.value === MERGE_KEY) {
          items[i] = new Merge(items[i]);
          const sources = items[i].value.items;
          let error = null;
          sources.some((node) => {
            if (node instanceof Alias) {
              const {
                type
              } = node.source;
              if (type === PlainValue.Type.MAP || type === PlainValue.Type.FLOW_MAP)
                return false;
              return error = "Merge nodes aliases can only point to maps";
            }
            return error = "Merge nodes can only have Alias nodes as values";
          });
          if (error)
            doc.errors.push(new PlainValue.YAMLSemanticError(cst, error));
        } else {
          for (let j = i + 1; j < items.length; ++j) {
            const {
              key: jKey
            } = items[j];
            if (iKey === jKey || iKey && jKey && Object.prototype.hasOwnProperty.call(iKey, "value") && iKey.value === jKey.value) {
              const msg = `Map keys must be unique; "${iKey}" is repeated`;
              doc.errors.push(new PlainValue.YAMLSemanticError(cst, msg));
              break;
            }
          }
        }
      }
      if (hasCollectionKey && !doc.options.mapAsMap) {
        const warn = "Keys with collection values will be stringified as YAML due to JS Object restrictions. Use mapAsMap: true to avoid this.";
        doc.warnings.push(new PlainValue.YAMLWarning(cst, warn));
      }
      cst.resolved = map;
      return map;
    }
    var valueHasPairComment = ({
      context: {
        lineStart,
        node,
        src
      },
      props
    }) => {
      if (props.length === 0)
        return false;
      const {
        start
      } = props[0];
      if (node && start > node.valueRange.start)
        return false;
      if (src[start] !== PlainValue.Char.COMMENT)
        return false;
      for (let i = lineStart; i < start; ++i)
        if (src[i] === "\n")
          return false;
      return true;
    };
    function resolvePairComment(item, pair) {
      if (!valueHasPairComment(item))
        return;
      const comment = item.getPropValue(0, PlainValue.Char.COMMENT, true);
      let found = false;
      const cb = pair.value.commentBefore;
      if (cb && cb.startsWith(comment)) {
        pair.value.commentBefore = cb.substr(comment.length + 1);
        found = true;
      } else {
        const cc = pair.value.comment;
        if (!item.node && cc && cc.startsWith(comment)) {
          pair.value.comment = cc.substr(comment.length + 1);
          found = true;
        }
      }
      if (found)
        pair.comment = comment;
    }
    function resolveBlockMapItems(doc, cst) {
      const comments = [];
      const items = [];
      let key = void 0;
      let keyStart = null;
      for (let i = 0; i < cst.items.length; ++i) {
        const item = cst.items[i];
        switch (item.type) {
          case PlainValue.Type.BLANK_LINE:
            comments.push({
              afterKey: !!key,
              before: items.length
            });
            break;
          case PlainValue.Type.COMMENT:
            comments.push({
              afterKey: !!key,
              before: items.length,
              comment: item.comment
            });
            break;
          case PlainValue.Type.MAP_KEY:
            if (key !== void 0)
              items.push(new Pair(key));
            if (item.error)
              doc.errors.push(item.error);
            key = resolveNode(doc, item.node);
            keyStart = null;
            break;
          case PlainValue.Type.MAP_VALUE:
            {
              if (key === void 0)
                key = null;
              if (item.error)
                doc.errors.push(item.error);
              if (!item.context.atLineStart && item.node && item.node.type === PlainValue.Type.MAP && !item.node.context.atLineStart) {
                const msg = "Nested mappings are not allowed in compact mappings";
                doc.errors.push(new PlainValue.YAMLSemanticError(item.node, msg));
              }
              let valueNode = item.node;
              if (!valueNode && item.props.length > 0) {
                valueNode = new PlainValue.PlainValue(PlainValue.Type.PLAIN, []);
                valueNode.context = {
                  parent: item,
                  src: item.context.src
                };
                const pos = item.range.start + 1;
                valueNode.range = {
                  start: pos,
                  end: pos
                };
                valueNode.valueRange = {
                  start: pos,
                  end: pos
                };
                if (typeof item.range.origStart === "number") {
                  const origPos = item.range.origStart + 1;
                  valueNode.range.origStart = valueNode.range.origEnd = origPos;
                  valueNode.valueRange.origStart = valueNode.valueRange.origEnd = origPos;
                }
              }
              const pair = new Pair(key, resolveNode(doc, valueNode));
              resolvePairComment(item, pair);
              items.push(pair);
              if (key && typeof keyStart === "number") {
                if (item.range.start > keyStart + 1024)
                  doc.errors.push(getLongKeyError(cst, key));
              }
              key = void 0;
              keyStart = null;
            }
            break;
          default:
            if (key !== void 0)
              items.push(new Pair(key));
            key = resolveNode(doc, item);
            keyStart = item.range.start;
            if (item.error)
              doc.errors.push(item.error);
            next:
              for (let j = i + 1; ; ++j) {
                const nextItem = cst.items[j];
                switch (nextItem && nextItem.type) {
                  case PlainValue.Type.BLANK_LINE:
                  case PlainValue.Type.COMMENT:
                    continue next;
                  case PlainValue.Type.MAP_VALUE:
                    break next;
                  default: {
                    const msg = "Implicit map keys need to be followed by map values";
                    doc.errors.push(new PlainValue.YAMLSemanticError(item, msg));
                    break next;
                  }
                }
              }
            if (item.valueRangeContainsNewline) {
              const msg = "Implicit map keys need to be on a single line";
              doc.errors.push(new PlainValue.YAMLSemanticError(item, msg));
            }
        }
      }
      if (key !== void 0)
        items.push(new Pair(key));
      return {
        comments,
        items
      };
    }
    function resolveFlowMapItems(doc, cst) {
      const comments = [];
      const items = [];
      let key = void 0;
      let explicitKey = false;
      let next = "{";
      for (let i = 0; i < cst.items.length; ++i) {
        const item = cst.items[i];
        if (typeof item.char === "string") {
          const {
            char,
            offset
          } = item;
          if (char === "?" && key === void 0 && !explicitKey) {
            explicitKey = true;
            next = ":";
            continue;
          }
          if (char === ":") {
            if (key === void 0)
              key = null;
            if (next === ":") {
              next = ",";
              continue;
            }
          } else {
            if (explicitKey) {
              if (key === void 0 && char !== ",")
                key = null;
              explicitKey = false;
            }
            if (key !== void 0) {
              items.push(new Pair(key));
              key = void 0;
              if (char === ",") {
                next = ":";
                continue;
              }
            }
          }
          if (char === "}") {
            if (i === cst.items.length - 1)
              continue;
          } else if (char === next) {
            next = ":";
            continue;
          }
          const msg = `Flow map contains an unexpected ${char}`;
          const err = new PlainValue.YAMLSyntaxError(cst, msg);
          err.offset = offset;
          doc.errors.push(err);
        } else if (item.type === PlainValue.Type.BLANK_LINE) {
          comments.push({
            afterKey: !!key,
            before: items.length
          });
        } else if (item.type === PlainValue.Type.COMMENT) {
          checkFlowCommentSpace(doc.errors, item);
          comments.push({
            afterKey: !!key,
            before: items.length,
            comment: item.comment
          });
        } else if (key === void 0) {
          if (next === ",")
            doc.errors.push(new PlainValue.YAMLSemanticError(item, "Separator , missing in flow map"));
          key = resolveNode(doc, item);
        } else {
          if (next !== ",")
            doc.errors.push(new PlainValue.YAMLSemanticError(item, "Indicator : missing in flow map entry"));
          items.push(new Pair(key, resolveNode(doc, item)));
          key = void 0;
          explicitKey = false;
        }
      }
      checkFlowCollectionEnd(doc.errors, cst);
      if (key !== void 0)
        items.push(new Pair(key));
      return {
        comments,
        items
      };
    }
    function resolveSeq(doc, cst) {
      if (cst.type !== PlainValue.Type.SEQ && cst.type !== PlainValue.Type.FLOW_SEQ) {
        const msg = `A ${cst.type} node cannot be resolved as a sequence`;
        doc.errors.push(new PlainValue.YAMLSyntaxError(cst, msg));
        return null;
      }
      const {
        comments,
        items
      } = cst.type === PlainValue.Type.FLOW_SEQ ? resolveFlowSeqItems(doc, cst) : resolveBlockSeqItems(doc, cst);
      const seq = new YAMLSeq();
      seq.items = items;
      resolveComments(seq, comments);
      if (!doc.options.mapAsMap && items.some((it) => it instanceof Pair && it.key instanceof Collection)) {
        const warn = "Keys with collection values will be stringified as YAML due to JS Object restrictions. Use mapAsMap: true to avoid this.";
        doc.warnings.push(new PlainValue.YAMLWarning(cst, warn));
      }
      cst.resolved = seq;
      return seq;
    }
    function resolveBlockSeqItems(doc, cst) {
      const comments = [];
      const items = [];
      for (let i = 0; i < cst.items.length; ++i) {
        const item = cst.items[i];
        switch (item.type) {
          case PlainValue.Type.BLANK_LINE:
            comments.push({
              before: items.length
            });
            break;
          case PlainValue.Type.COMMENT:
            comments.push({
              comment: item.comment,
              before: items.length
            });
            break;
          case PlainValue.Type.SEQ_ITEM:
            if (item.error)
              doc.errors.push(item.error);
            items.push(resolveNode(doc, item.node));
            if (item.hasProps) {
              const msg = "Sequence items cannot have tags or anchors before the - indicator";
              doc.errors.push(new PlainValue.YAMLSemanticError(item, msg));
            }
            break;
          default:
            if (item.error)
              doc.errors.push(item.error);
            doc.errors.push(new PlainValue.YAMLSyntaxError(item, `Unexpected ${item.type} node in sequence`));
        }
      }
      return {
        comments,
        items
      };
    }
    function resolveFlowSeqItems(doc, cst) {
      const comments = [];
      const items = [];
      let explicitKey = false;
      let key = void 0;
      let keyStart = null;
      let next = "[";
      let prevItem = null;
      for (let i = 0; i < cst.items.length; ++i) {
        const item = cst.items[i];
        if (typeof item.char === "string") {
          const {
            char,
            offset
          } = item;
          if (char !== ":" && (explicitKey || key !== void 0)) {
            if (explicitKey && key === void 0)
              key = next ? items.pop() : null;
            items.push(new Pair(key));
            explicitKey = false;
            key = void 0;
            keyStart = null;
          }
          if (char === next) {
            next = null;
          } else if (!next && char === "?") {
            explicitKey = true;
          } else if (next !== "[" && char === ":" && key === void 0) {
            if (next === ",") {
              key = items.pop();
              if (key instanceof Pair) {
                const msg = "Chaining flow sequence pairs is invalid";
                const err = new PlainValue.YAMLSemanticError(cst, msg);
                err.offset = offset;
                doc.errors.push(err);
              }
              if (!explicitKey && typeof keyStart === "number") {
                const keyEnd = item.range ? item.range.start : item.offset;
                if (keyEnd > keyStart + 1024)
                  doc.errors.push(getLongKeyError(cst, key));
                const {
                  src
                } = prevItem.context;
                for (let i2 = keyStart; i2 < keyEnd; ++i2)
                  if (src[i2] === "\n") {
                    const msg = "Implicit keys of flow sequence pairs need to be on a single line";
                    doc.errors.push(new PlainValue.YAMLSemanticError(prevItem, msg));
                    break;
                  }
              }
            } else {
              key = null;
            }
            keyStart = null;
            explicitKey = false;
            next = null;
          } else if (next === "[" || char !== "]" || i < cst.items.length - 1) {
            const msg = `Flow sequence contains an unexpected ${char}`;
            const err = new PlainValue.YAMLSyntaxError(cst, msg);
            err.offset = offset;
            doc.errors.push(err);
          }
        } else if (item.type === PlainValue.Type.BLANK_LINE) {
          comments.push({
            before: items.length
          });
        } else if (item.type === PlainValue.Type.COMMENT) {
          checkFlowCommentSpace(doc.errors, item);
          comments.push({
            comment: item.comment,
            before: items.length
          });
        } else {
          if (next) {
            const msg = `Expected a ${next} in flow sequence`;
            doc.errors.push(new PlainValue.YAMLSemanticError(item, msg));
          }
          const value = resolveNode(doc, item);
          if (key === void 0) {
            items.push(value);
            prevItem = item;
          } else {
            items.push(new Pair(key, value));
            key = void 0;
          }
          keyStart = item.range.start;
          next = ",";
        }
      }
      checkFlowCollectionEnd(doc.errors, cst);
      if (key !== void 0)
        items.push(new Pair(key));
      return {
        comments,
        items
      };
    }
    exports.Alias = Alias;
    exports.Collection = Collection;
    exports.Merge = Merge;
    exports.Node = Node;
    exports.Pair = Pair;
    exports.Scalar = Scalar;
    exports.YAMLMap = YAMLMap;
    exports.YAMLSeq = YAMLSeq;
    exports.addComment = addComment;
    exports.binaryOptions = binaryOptions;
    exports.boolOptions = boolOptions;
    exports.findPair = findPair;
    exports.intOptions = intOptions;
    exports.isEmptyPath = isEmptyPath;
    exports.nullOptions = nullOptions;
    exports.resolveMap = resolveMap;
    exports.resolveNode = resolveNode;
    exports.resolveSeq = resolveSeq;
    exports.resolveString = resolveString;
    exports.strOptions = strOptions;
    exports.stringifyNumber = stringifyNumber;
    exports.stringifyString = stringifyString;
    exports.toJSON = toJSON;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/warnings-793925ce.js
var require_warnings_793925ce = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/warnings-793925ce.js"(exports) {
    "use strict";
    var PlainValue = require_PlainValue_516d5bc2();
    var resolveSeq = require_resolveSeq_95613e94();
    var binary = {
      identify: (value) => value instanceof Uint8Array,
      // Buffer inherits from Uint8Array
      default: false,
      tag: "tag:yaml.org,2002:binary",
      /**
       * Returns a Buffer in node and an Uint8Array in browsers
       *
       * To use the resulting buffer as an image, you'll want to do something like:
       *
       *   const blob = new Blob([buffer], { type: 'image/jpeg' })
       *   document.querySelector('#photo').src = URL.createObjectURL(blob)
       */
      resolve: (doc, node) => {
        const src = resolveSeq.resolveString(doc, node);
        if (typeof Buffer === "function") {
          return Buffer.from(src, "base64");
        } else if (typeof atob === "function") {
          const str = atob(src.replace(/[\n\r]/g, ""));
          const buffer = new Uint8Array(str.length);
          for (let i = 0; i < str.length; ++i)
            buffer[i] = str.charCodeAt(i);
          return buffer;
        } else {
          const msg = "This environment does not support reading binary tags; either Buffer or atob is required";
          doc.errors.push(new PlainValue.YAMLReferenceError(node, msg));
          return null;
        }
      },
      options: resolveSeq.binaryOptions,
      stringify: ({
        comment,
        type,
        value
      }, ctx, onComment, onChompKeep) => {
        let src;
        if (typeof Buffer === "function") {
          src = value instanceof Buffer ? value.toString("base64") : Buffer.from(value.buffer).toString("base64");
        } else if (typeof btoa === "function") {
          let s = "";
          for (let i = 0; i < value.length; ++i)
            s += String.fromCharCode(value[i]);
          src = btoa(s);
        } else {
          throw new Error("This environment does not support writing binary tags; either Buffer or btoa is required");
        }
        if (!type)
          type = resolveSeq.binaryOptions.defaultType;
        if (type === PlainValue.Type.QUOTE_DOUBLE) {
          value = src;
        } else {
          const {
            lineWidth
          } = resolveSeq.binaryOptions;
          const n = Math.ceil(src.length / lineWidth);
          const lines = new Array(n);
          for (let i = 0, o = 0; i < n; ++i, o += lineWidth) {
            lines[i] = src.substr(o, lineWidth);
          }
          value = lines.join(type === PlainValue.Type.BLOCK_LITERAL ? "\n" : " ");
        }
        return resolveSeq.stringifyString({
          comment,
          type,
          value
        }, ctx, onComment, onChompKeep);
      }
    };
    function parsePairs(doc, cst) {
      const seq = resolveSeq.resolveSeq(doc, cst);
      for (let i = 0; i < seq.items.length; ++i) {
        let item = seq.items[i];
        if (item instanceof resolveSeq.Pair)
          continue;
        else if (item instanceof resolveSeq.YAMLMap) {
          if (item.items.length > 1) {
            const msg = "Each pair must have its own sequence indicator";
            throw new PlainValue.YAMLSemanticError(cst, msg);
          }
          const pair = item.items[0] || new resolveSeq.Pair();
          if (item.commentBefore)
            pair.commentBefore = pair.commentBefore ? `${item.commentBefore}
${pair.commentBefore}` : item.commentBefore;
          if (item.comment)
            pair.comment = pair.comment ? `${item.comment}
${pair.comment}` : item.comment;
          item = pair;
        }
        seq.items[i] = item instanceof resolveSeq.Pair ? item : new resolveSeq.Pair(item);
      }
      return seq;
    }
    function createPairs(schema, iterable, ctx) {
      const pairs2 = new resolveSeq.YAMLSeq(schema);
      pairs2.tag = "tag:yaml.org,2002:pairs";
      for (const it of iterable) {
        let key, value;
        if (Array.isArray(it)) {
          if (it.length === 2) {
            key = it[0];
            value = it[1];
          } else
            throw new TypeError(`Expected [key, value] tuple: ${it}`);
        } else if (it && it instanceof Object) {
          const keys = Object.keys(it);
          if (keys.length === 1) {
            key = keys[0];
            value = it[key];
          } else
            throw new TypeError(`Expected { key: value } tuple: ${it}`);
        } else {
          key = it;
        }
        const pair = schema.createPair(key, value, ctx);
        pairs2.items.push(pair);
      }
      return pairs2;
    }
    var pairs = {
      default: false,
      tag: "tag:yaml.org,2002:pairs",
      resolve: parsePairs,
      createNode: createPairs
    };
    var YAMLOMap = class _YAMLOMap extends resolveSeq.YAMLSeq {
      constructor() {
        super();
        PlainValue._defineProperty(this, "add", resolveSeq.YAMLMap.prototype.add.bind(this));
        PlainValue._defineProperty(this, "delete", resolveSeq.YAMLMap.prototype.delete.bind(this));
        PlainValue._defineProperty(this, "get", resolveSeq.YAMLMap.prototype.get.bind(this));
        PlainValue._defineProperty(this, "has", resolveSeq.YAMLMap.prototype.has.bind(this));
        PlainValue._defineProperty(this, "set", resolveSeq.YAMLMap.prototype.set.bind(this));
        this.tag = _YAMLOMap.tag;
      }
      toJSON(_, ctx) {
        const map = /* @__PURE__ */ new Map();
        if (ctx && ctx.onCreate)
          ctx.onCreate(map);
        for (const pair of this.items) {
          let key, value;
          if (pair instanceof resolveSeq.Pair) {
            key = resolveSeq.toJSON(pair.key, "", ctx);
            value = resolveSeq.toJSON(pair.value, key, ctx);
          } else {
            key = resolveSeq.toJSON(pair, "", ctx);
          }
          if (map.has(key))
            throw new Error("Ordered maps must not include duplicate keys");
          map.set(key, value);
        }
        return map;
      }
    };
    PlainValue._defineProperty(YAMLOMap, "tag", "tag:yaml.org,2002:omap");
    function parseOMap(doc, cst) {
      const pairs2 = parsePairs(doc, cst);
      const seenKeys = [];
      for (const {
        key
      } of pairs2.items) {
        if (key instanceof resolveSeq.Scalar) {
          if (seenKeys.includes(key.value)) {
            const msg = "Ordered maps must not include duplicate keys";
            throw new PlainValue.YAMLSemanticError(cst, msg);
          } else {
            seenKeys.push(key.value);
          }
        }
      }
      return Object.assign(new YAMLOMap(), pairs2);
    }
    function createOMap(schema, iterable, ctx) {
      const pairs2 = createPairs(schema, iterable, ctx);
      const omap2 = new YAMLOMap();
      omap2.items = pairs2.items;
      return omap2;
    }
    var omap = {
      identify: (value) => value instanceof Map,
      nodeClass: YAMLOMap,
      default: false,
      tag: "tag:yaml.org,2002:omap",
      resolve: parseOMap,
      createNode: createOMap
    };
    var YAMLSet = class _YAMLSet extends resolveSeq.YAMLMap {
      constructor() {
        super();
        this.tag = _YAMLSet.tag;
      }
      add(key) {
        const pair = key instanceof resolveSeq.Pair ? key : new resolveSeq.Pair(key);
        const prev = resolveSeq.findPair(this.items, pair.key);
        if (!prev)
          this.items.push(pair);
      }
      get(key, keepPair) {
        const pair = resolveSeq.findPair(this.items, key);
        return !keepPair && pair instanceof resolveSeq.Pair ? pair.key instanceof resolveSeq.Scalar ? pair.key.value : pair.key : pair;
      }
      set(key, value) {
        if (typeof value !== "boolean")
          throw new Error(`Expected boolean value for set(key, value) in a YAML set, not ${typeof value}`);
        const prev = resolveSeq.findPair(this.items, key);
        if (prev && !value) {
          this.items.splice(this.items.indexOf(prev), 1);
        } else if (!prev && value) {
          this.items.push(new resolveSeq.Pair(key));
        }
      }
      toJSON(_, ctx) {
        return super.toJSON(_, ctx, Set);
      }
      toString(ctx, onComment, onChompKeep) {
        if (!ctx)
          return JSON.stringify(this);
        if (this.hasAllNullValues())
          return super.toString(ctx, onComment, onChompKeep);
        else
          throw new Error("Set items must all have null values");
      }
    };
    PlainValue._defineProperty(YAMLSet, "tag", "tag:yaml.org,2002:set");
    function parseSet(doc, cst) {
      const map = resolveSeq.resolveMap(doc, cst);
      if (!map.hasAllNullValues())
        throw new PlainValue.YAMLSemanticError(cst, "Set items must all have null values");
      return Object.assign(new YAMLSet(), map);
    }
    function createSet(schema, iterable, ctx) {
      const set2 = new YAMLSet();
      for (const value of iterable)
        set2.items.push(schema.createPair(value, null, ctx));
      return set2;
    }
    var set = {
      identify: (value) => value instanceof Set,
      nodeClass: YAMLSet,
      default: false,
      tag: "tag:yaml.org,2002:set",
      resolve: parseSet,
      createNode: createSet
    };
    var parseSexagesimal = (sign, parts) => {
      const n = parts.split(":").reduce((n2, p) => n2 * 60 + Number(p), 0);
      return sign === "-" ? -n : n;
    };
    var stringifySexagesimal = ({
      value
    }) => {
      if (isNaN(value) || !isFinite(value))
        return resolveSeq.stringifyNumber(value);
      let sign = "";
      if (value < 0) {
        sign = "-";
        value = Math.abs(value);
      }
      const parts = [value % 60];
      if (value < 60) {
        parts.unshift(0);
      } else {
        value = Math.round((value - parts[0]) / 60);
        parts.unshift(value % 60);
        if (value >= 60) {
          value = Math.round((value - parts[0]) / 60);
          parts.unshift(value);
        }
      }
      return sign + parts.map((n) => n < 10 ? "0" + String(n) : String(n)).join(":").replace(/000000\d*$/, "");
    };
    var intTime = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "TIME",
      test: /^([-+]?)([0-9][0-9_]*(?::[0-5]?[0-9])+)$/,
      resolve: (str, sign, parts) => parseSexagesimal(sign, parts.replace(/_/g, "")),
      stringify: stringifySexagesimal
    };
    var floatTime = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      format: "TIME",
      test: /^([-+]?)([0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*)$/,
      resolve: (str, sign, parts) => parseSexagesimal(sign, parts.replace(/_/g, "")),
      stringify: stringifySexagesimal
    };
    var timestamp = {
      identify: (value) => value instanceof Date,
      default: true,
      tag: "tag:yaml.org,2002:timestamp",
      // If the time zone is omitted, the timestamp is assumed to be specified in UTC. The time part
      // may be omitted altogether, resulting in a date format. In such a case, the time part is
      // assumed to be 00:00:00Z (start of day, UTC).
      test: RegExp("^(?:([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})(?:(?:t|T|[ \\t]+)([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2}(\\.[0-9]+)?)(?:[ \\t]*(Z|[-+][012]?[0-9](?::[0-9]{2})?))?)?)$"),
      resolve: (str, year, month, day, hour, minute, second, millisec, tz) => {
        if (millisec)
          millisec = (millisec + "00").substr(1, 3);
        let date = Date.UTC(year, month - 1, day, hour || 0, minute || 0, second || 0, millisec || 0);
        if (tz && tz !== "Z") {
          let d = parseSexagesimal(tz[0], tz.slice(1));
          if (Math.abs(d) < 30)
            d *= 60;
          date -= 6e4 * d;
        }
        return new Date(date);
      },
      stringify: ({
        value
      }) => value.toISOString().replace(/((T00:00)?:00)?\.000Z$/, "")
    };
    function shouldWarn(deprecation) {
      const env = typeof process !== "undefined" && process.env || {};
      if (deprecation) {
        if (typeof YAML_SILENCE_DEPRECATION_WARNINGS !== "undefined")
          return !YAML_SILENCE_DEPRECATION_WARNINGS;
        return !env.YAML_SILENCE_DEPRECATION_WARNINGS;
      }
      if (typeof YAML_SILENCE_WARNINGS !== "undefined")
        return !YAML_SILENCE_WARNINGS;
      return !env.YAML_SILENCE_WARNINGS;
    }
    function warn(warning, type) {
      if (shouldWarn(false)) {
        const emit = typeof process !== "undefined" && process.emitWarning;
        if (emit)
          emit(warning, type);
        else {
          console.warn(type ? `${type}: ${warning}` : warning);
        }
      }
    }
    function warnFileDeprecation(filename) {
      if (shouldWarn(true)) {
        const path = filename.replace(/.*yaml[/\\]/i, "").replace(/\.js$/, "").replace(/\\/g, "/");
        warn(`The endpoint 'yaml/${path}' will be removed in a future release.`, "DeprecationWarning");
      }
    }
    var warned = {};
    function warnOptionDeprecation(name, alternative) {
      if (!warned[name] && shouldWarn(true)) {
        warned[name] = true;
        let msg = `The option '${name}' will be removed in a future release`;
        msg += alternative ? `, use '${alternative}' instead.` : ".";
        warn(msg, "DeprecationWarning");
      }
    }
    exports.binary = binary;
    exports.floatTime = floatTime;
    exports.intTime = intTime;
    exports.omap = omap;
    exports.pairs = pairs;
    exports.set = set;
    exports.timestamp = timestamp;
    exports.warn = warn;
    exports.warnFileDeprecation = warnFileDeprecation;
    exports.warnOptionDeprecation = warnOptionDeprecation;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/Schema-bcc6c2d7.js
var require_Schema_bcc6c2d7 = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/Schema-bcc6c2d7.js"(exports) {
    "use strict";
    var PlainValue = require_PlainValue_516d5bc2();
    var resolveSeq = require_resolveSeq_95613e94();
    var warnings = require_warnings_793925ce();
    function createMap(schema, obj, ctx) {
      const map2 = new resolveSeq.YAMLMap(schema);
      if (obj instanceof Map) {
        for (const [key, value] of obj)
          map2.items.push(schema.createPair(key, value, ctx));
      } else if (obj && typeof obj === "object") {
        for (const key of Object.keys(obj))
          map2.items.push(schema.createPair(key, obj[key], ctx));
      }
      if (typeof schema.sortMapEntries === "function") {
        map2.items.sort(schema.sortMapEntries);
      }
      return map2;
    }
    var map = {
      createNode: createMap,
      default: true,
      nodeClass: resolveSeq.YAMLMap,
      tag: "tag:yaml.org,2002:map",
      resolve: resolveSeq.resolveMap
    };
    function createSeq(schema, obj, ctx) {
      const seq2 = new resolveSeq.YAMLSeq(schema);
      if (obj && obj[Symbol.iterator]) {
        for (const it of obj) {
          const v = schema.createNode(it, ctx.wrapScalars, null, ctx);
          seq2.items.push(v);
        }
      }
      return seq2;
    }
    var seq = {
      createNode: createSeq,
      default: true,
      nodeClass: resolveSeq.YAMLSeq,
      tag: "tag:yaml.org,2002:seq",
      resolve: resolveSeq.resolveSeq
    };
    var string = {
      identify: (value) => typeof value === "string",
      default: true,
      tag: "tag:yaml.org,2002:str",
      resolve: resolveSeq.resolveString,
      stringify(item, ctx, onComment, onChompKeep) {
        ctx = Object.assign({
          actualString: true
        }, ctx);
        return resolveSeq.stringifyString(item, ctx, onComment, onChompKeep);
      },
      options: resolveSeq.strOptions
    };
    var failsafe = [map, seq, string];
    var intIdentify$2 = (value) => typeof value === "bigint" || Number.isInteger(value);
    var intResolve$1 = (src, part, radix) => resolveSeq.intOptions.asBigInt ? BigInt(src) : parseInt(part, radix);
    function intStringify$1(node, radix, prefix) {
      const {
        value
      } = node;
      if (intIdentify$2(value) && value >= 0)
        return prefix + value.toString(radix);
      return resolveSeq.stringifyNumber(node);
    }
    var nullObj = {
      identify: (value) => value == null,
      createNode: (schema, value, ctx) => ctx.wrapScalars ? new resolveSeq.Scalar(null) : null,
      default: true,
      tag: "tag:yaml.org,2002:null",
      test: /^(?:~|[Nn]ull|NULL)?$/,
      resolve: () => null,
      options: resolveSeq.nullOptions,
      stringify: () => resolveSeq.nullOptions.nullStr
    };
    var boolObj = {
      identify: (value) => typeof value === "boolean",
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^(?:[Tt]rue|TRUE|[Ff]alse|FALSE)$/,
      resolve: (str) => str[0] === "t" || str[0] === "T",
      options: resolveSeq.boolOptions,
      stringify: ({
        value
      }) => value ? resolveSeq.boolOptions.trueStr : resolveSeq.boolOptions.falseStr
    };
    var octObj = {
      identify: (value) => intIdentify$2(value) && value >= 0,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "OCT",
      test: /^0o([0-7]+)$/,
      resolve: (str, oct) => intResolve$1(str, oct, 8),
      options: resolveSeq.intOptions,
      stringify: (node) => intStringify$1(node, 8, "0o")
    };
    var intObj = {
      identify: intIdentify$2,
      default: true,
      tag: "tag:yaml.org,2002:int",
      test: /^[-+]?[0-9]+$/,
      resolve: (str) => intResolve$1(str, str, 10),
      options: resolveSeq.intOptions,
      stringify: resolveSeq.stringifyNumber
    };
    var hexObj = {
      identify: (value) => intIdentify$2(value) && value >= 0,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "HEX",
      test: /^0x([0-9a-fA-F]+)$/,
      resolve: (str, hex) => intResolve$1(str, hex, 16),
      options: resolveSeq.intOptions,
      stringify: (node) => intStringify$1(node, 16, "0x")
    };
    var nanObj = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^(?:[-+]?\.inf|(\.nan))$/i,
      resolve: (str, nan) => nan ? NaN : str[0] === "-" ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY,
      stringify: resolveSeq.stringifyNumber
    };
    var expObj = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      format: "EXP",
      test: /^[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+$/,
      resolve: (str) => parseFloat(str),
      stringify: ({
        value
      }) => Number(value).toExponential()
    };
    var floatObj = {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^[-+]?(?:\.([0-9]+)|[0-9]+\.([0-9]*))$/,
      resolve(str, frac1, frac2) {
        const frac = frac1 || frac2;
        const node = new resolveSeq.Scalar(parseFloat(str));
        if (frac && frac[frac.length - 1] === "0")
          node.minFractionDigits = frac.length;
        return node;
      },
      stringify: resolveSeq.stringifyNumber
    };
    var core = failsafe.concat([nullObj, boolObj, octObj, intObj, hexObj, nanObj, expObj, floatObj]);
    var intIdentify$1 = (value) => typeof value === "bigint" || Number.isInteger(value);
    var stringifyJSON = ({
      value
    }) => JSON.stringify(value);
    var json = [map, seq, {
      identify: (value) => typeof value === "string",
      default: true,
      tag: "tag:yaml.org,2002:str",
      resolve: resolveSeq.resolveString,
      stringify: stringifyJSON
    }, {
      identify: (value) => value == null,
      createNode: (schema, value, ctx) => ctx.wrapScalars ? new resolveSeq.Scalar(null) : null,
      default: true,
      tag: "tag:yaml.org,2002:null",
      test: /^null$/,
      resolve: () => null,
      stringify: stringifyJSON
    }, {
      identify: (value) => typeof value === "boolean",
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^true|false$/,
      resolve: (str) => str === "true",
      stringify: stringifyJSON
    }, {
      identify: intIdentify$1,
      default: true,
      tag: "tag:yaml.org,2002:int",
      test: /^-?(?:0|[1-9][0-9]*)$/,
      resolve: (str) => resolveSeq.intOptions.asBigInt ? BigInt(str) : parseInt(str, 10),
      stringify: ({
        value
      }) => intIdentify$1(value) ? value.toString() : JSON.stringify(value)
    }, {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*)?(?:[eE][-+]?[0-9]+)?$/,
      resolve: (str) => parseFloat(str),
      stringify: stringifyJSON
    }];
    json.scalarFallback = (str) => {
      throw new SyntaxError(`Unresolved plain scalar ${JSON.stringify(str)}`);
    };
    var boolStringify = ({
      value
    }) => value ? resolveSeq.boolOptions.trueStr : resolveSeq.boolOptions.falseStr;
    var intIdentify = (value) => typeof value === "bigint" || Number.isInteger(value);
    function intResolve(sign, src, radix) {
      let str = src.replace(/_/g, "");
      if (resolveSeq.intOptions.asBigInt) {
        switch (radix) {
          case 2:
            str = `0b${str}`;
            break;
          case 8:
            str = `0o${str}`;
            break;
          case 16:
            str = `0x${str}`;
            break;
        }
        const n2 = BigInt(str);
        return sign === "-" ? BigInt(-1) * n2 : n2;
      }
      const n = parseInt(str, radix);
      return sign === "-" ? -1 * n : n;
    }
    function intStringify(node, radix, prefix) {
      const {
        value
      } = node;
      if (intIdentify(value)) {
        const str = value.toString(radix);
        return value < 0 ? "-" + prefix + str.substr(1) : prefix + str;
      }
      return resolveSeq.stringifyNumber(node);
    }
    var yaml11 = failsafe.concat([{
      identify: (value) => value == null,
      createNode: (schema, value, ctx) => ctx.wrapScalars ? new resolveSeq.Scalar(null) : null,
      default: true,
      tag: "tag:yaml.org,2002:null",
      test: /^(?:~|[Nn]ull|NULL)?$/,
      resolve: () => null,
      options: resolveSeq.nullOptions,
      stringify: () => resolveSeq.nullOptions.nullStr
    }, {
      identify: (value) => typeof value === "boolean",
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^(?:Y|y|[Yy]es|YES|[Tt]rue|TRUE|[Oo]n|ON)$/,
      resolve: () => true,
      options: resolveSeq.boolOptions,
      stringify: boolStringify
    }, {
      identify: (value) => typeof value === "boolean",
      default: true,
      tag: "tag:yaml.org,2002:bool",
      test: /^(?:N|n|[Nn]o|NO|[Ff]alse|FALSE|[Oo]ff|OFF)$/i,
      resolve: () => false,
      options: resolveSeq.boolOptions,
      stringify: boolStringify
    }, {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "BIN",
      test: /^([-+]?)0b([0-1_]+)$/,
      resolve: (str, sign, bin) => intResolve(sign, bin, 2),
      stringify: (node) => intStringify(node, 2, "0b")
    }, {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "OCT",
      test: /^([-+]?)0([0-7_]+)$/,
      resolve: (str, sign, oct) => intResolve(sign, oct, 8),
      stringify: (node) => intStringify(node, 8, "0")
    }, {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      test: /^([-+]?)([0-9][0-9_]*)$/,
      resolve: (str, sign, abs) => intResolve(sign, abs, 10),
      stringify: resolveSeq.stringifyNumber
    }, {
      identify: intIdentify,
      default: true,
      tag: "tag:yaml.org,2002:int",
      format: "HEX",
      test: /^([-+]?)0x([0-9a-fA-F_]+)$/,
      resolve: (str, sign, hex) => intResolve(sign, hex, 16),
      stringify: (node) => intStringify(node, 16, "0x")
    }, {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^(?:[-+]?\.inf|(\.nan))$/i,
      resolve: (str, nan) => nan ? NaN : str[0] === "-" ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY,
      stringify: resolveSeq.stringifyNumber
    }, {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      format: "EXP",
      test: /^[-+]?([0-9][0-9_]*)?(\.[0-9_]*)?[eE][-+]?[0-9]+$/,
      resolve: (str) => parseFloat(str.replace(/_/g, "")),
      stringify: ({
        value
      }) => Number(value).toExponential()
    }, {
      identify: (value) => typeof value === "number",
      default: true,
      tag: "tag:yaml.org,2002:float",
      test: /^[-+]?(?:[0-9][0-9_]*)?\.([0-9_]*)$/,
      resolve(str, frac) {
        const node = new resolveSeq.Scalar(parseFloat(str.replace(/_/g, "")));
        if (frac) {
          const f = frac.replace(/_/g, "");
          if (f[f.length - 1] === "0")
            node.minFractionDigits = f.length;
        }
        return node;
      },
      stringify: resolveSeq.stringifyNumber
    }], warnings.binary, warnings.omap, warnings.pairs, warnings.set, warnings.intTime, warnings.floatTime, warnings.timestamp);
    var schemas = {
      core,
      failsafe,
      json,
      yaml11
    };
    var tags = {
      binary: warnings.binary,
      bool: boolObj,
      float: floatObj,
      floatExp: expObj,
      floatNaN: nanObj,
      floatTime: warnings.floatTime,
      int: intObj,
      intHex: hexObj,
      intOct: octObj,
      intTime: warnings.intTime,
      map,
      null: nullObj,
      omap: warnings.omap,
      pairs: warnings.pairs,
      seq,
      set: warnings.set,
      timestamp: warnings.timestamp
    };
    function findTagObject(value, tagName, tags2) {
      if (tagName) {
        const match = tags2.filter((t) => t.tag === tagName);
        const tagObj = match.find((t) => !t.format) || match[0];
        if (!tagObj)
          throw new Error(`Tag ${tagName} not found`);
        return tagObj;
      }
      return tags2.find((t) => (t.identify && t.identify(value) || t.class && value instanceof t.class) && !t.format);
    }
    function createNode(value, tagName, ctx) {
      if (value instanceof resolveSeq.Node)
        return value;
      const {
        defaultPrefix,
        onTagObj,
        prevObjects,
        schema,
        wrapScalars
      } = ctx;
      if (tagName && tagName.startsWith("!!"))
        tagName = defaultPrefix + tagName.slice(2);
      let tagObj = findTagObject(value, tagName, schema.tags);
      if (!tagObj) {
        if (typeof value.toJSON === "function")
          value = value.toJSON();
        if (!value || typeof value !== "object")
          return wrapScalars ? new resolveSeq.Scalar(value) : value;
        tagObj = value instanceof Map ? map : value[Symbol.iterator] ? seq : map;
      }
      if (onTagObj) {
        onTagObj(tagObj);
        delete ctx.onTagObj;
      }
      const obj = {
        value: void 0,
        node: void 0
      };
      if (value && typeof value === "object" && prevObjects) {
        const prev = prevObjects.get(value);
        if (prev) {
          const alias = new resolveSeq.Alias(prev);
          ctx.aliasNodes.push(alias);
          return alias;
        }
        obj.value = value;
        prevObjects.set(value, obj);
      }
      obj.node = tagObj.createNode ? tagObj.createNode(ctx.schema, value, ctx) : wrapScalars ? new resolveSeq.Scalar(value) : value;
      if (tagName && obj.node instanceof resolveSeq.Node)
        obj.node.tag = tagName;
      return obj.node;
    }
    function getSchemaTags(schemas2, knownTags, customTags, schemaId) {
      let tags2 = schemas2[schemaId.replace(/\W/g, "")];
      if (!tags2) {
        const keys = Object.keys(schemas2).map((key) => JSON.stringify(key)).join(", ");
        throw new Error(`Unknown schema "${schemaId}"; use one of ${keys}`);
      }
      if (Array.isArray(customTags)) {
        for (const tag of customTags)
          tags2 = tags2.concat(tag);
      } else if (typeof customTags === "function") {
        tags2 = customTags(tags2.slice());
      }
      for (let i = 0; i < tags2.length; ++i) {
        const tag = tags2[i];
        if (typeof tag === "string") {
          const tagObj = knownTags[tag];
          if (!tagObj) {
            const keys = Object.keys(knownTags).map((key) => JSON.stringify(key)).join(", ");
            throw new Error(`Unknown custom tag "${tag}"; use one of ${keys}`);
          }
          tags2[i] = tagObj;
        }
      }
      return tags2;
    }
    var sortMapEntriesByKey = (a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0;
    var Schema = class _Schema {
      // TODO: remove in v2
      constructor({
        customTags,
        merge,
        schema,
        sortMapEntries,
        tags: deprecatedCustomTags
      }) {
        this.merge = !!merge;
        this.name = schema;
        this.sortMapEntries = sortMapEntries === true ? sortMapEntriesByKey : sortMapEntries || null;
        if (!customTags && deprecatedCustomTags)
          warnings.warnOptionDeprecation("tags", "customTags");
        this.tags = getSchemaTags(schemas, tags, customTags || deprecatedCustomTags, schema);
      }
      createNode(value, wrapScalars, tagName, ctx) {
        const baseCtx = {
          defaultPrefix: _Schema.defaultPrefix,
          schema: this,
          wrapScalars
        };
        const createCtx = ctx ? Object.assign(ctx, baseCtx) : baseCtx;
        return createNode(value, tagName, createCtx);
      }
      createPair(key, value, ctx) {
        if (!ctx)
          ctx = {
            wrapScalars: true
          };
        const k = this.createNode(key, ctx.wrapScalars, null, ctx);
        const v = this.createNode(value, ctx.wrapScalars, null, ctx);
        return new resolveSeq.Pair(k, v);
      }
    };
    PlainValue._defineProperty(Schema, "defaultPrefix", PlainValue.defaultTagPrefix);
    PlainValue._defineProperty(Schema, "defaultTags", PlainValue.defaultTags);
    exports.Schema = Schema;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/Document-a8d0fbf9.js
var require_Document_a8d0fbf9 = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/Document-a8d0fbf9.js"(exports) {
    "use strict";
    var PlainValue = require_PlainValue_516d5bc2();
    var resolveSeq = require_resolveSeq_95613e94();
    var Schema = require_Schema_bcc6c2d7();
    var defaultOptions = {
      anchorPrefix: "a",
      customTags: null,
      indent: 2,
      indentSeq: true,
      keepCstNodes: false,
      keepNodeTypes: true,
      keepBlobsInJSON: true,
      mapAsMap: false,
      maxAliasCount: 100,
      prettyErrors: false,
      // TODO Set true in v2
      simpleKeys: false,
      version: "1.2"
    };
    var scalarOptions = {
      get binary() {
        return resolveSeq.binaryOptions;
      },
      set binary(opt) {
        Object.assign(resolveSeq.binaryOptions, opt);
      },
      get bool() {
        return resolveSeq.boolOptions;
      },
      set bool(opt) {
        Object.assign(resolveSeq.boolOptions, opt);
      },
      get int() {
        return resolveSeq.intOptions;
      },
      set int(opt) {
        Object.assign(resolveSeq.intOptions, opt);
      },
      get null() {
        return resolveSeq.nullOptions;
      },
      set null(opt) {
        Object.assign(resolveSeq.nullOptions, opt);
      },
      get str() {
        return resolveSeq.strOptions;
      },
      set str(opt) {
        Object.assign(resolveSeq.strOptions, opt);
      }
    };
    var documentOptions = {
      "1.0": {
        schema: "yaml-1.1",
        merge: true,
        tagPrefixes: [{
          handle: "!",
          prefix: PlainValue.defaultTagPrefix
        }, {
          handle: "!!",
          prefix: "tag:private.yaml.org,2002:"
        }]
      },
      1.1: {
        schema: "yaml-1.1",
        merge: true,
        tagPrefixes: [{
          handle: "!",
          prefix: "!"
        }, {
          handle: "!!",
          prefix: PlainValue.defaultTagPrefix
        }]
      },
      1.2: {
        schema: "core",
        merge: false,
        tagPrefixes: [{
          handle: "!",
          prefix: "!"
        }, {
          handle: "!!",
          prefix: PlainValue.defaultTagPrefix
        }]
      }
    };
    function stringifyTag(doc, tag) {
      if ((doc.version || doc.options.version) === "1.0") {
        const priv = tag.match(/^tag:private\.yaml\.org,2002:([^:/]+)$/);
        if (priv)
          return "!" + priv[1];
        const vocab = tag.match(/^tag:([a-zA-Z0-9-]+)\.yaml\.org,2002:(.*)/);
        return vocab ? `!${vocab[1]}/${vocab[2]}` : `!${tag.replace(/^tag:/, "")}`;
      }
      let p = doc.tagPrefixes.find((p2) => tag.indexOf(p2.prefix) === 0);
      if (!p) {
        const dtp = doc.getDefaults().tagPrefixes;
        p = dtp && dtp.find((p2) => tag.indexOf(p2.prefix) === 0);
      }
      if (!p)
        return tag[0] === "!" ? tag : `!<${tag}>`;
      const suffix = tag.substr(p.prefix.length).replace(/[!,[\]{}]/g, (ch) => ({
        "!": "%21",
        ",": "%2C",
        "[": "%5B",
        "]": "%5D",
        "{": "%7B",
        "}": "%7D"
      })[ch]);
      return p.handle + suffix;
    }
    function getTagObject(tags, item) {
      if (item instanceof resolveSeq.Alias)
        return resolveSeq.Alias;
      if (item.tag) {
        const match = tags.filter((t) => t.tag === item.tag);
        if (match.length > 0)
          return match.find((t) => t.format === item.format) || match[0];
      }
      let tagObj, obj;
      if (item instanceof resolveSeq.Scalar) {
        obj = item.value;
        const match = tags.filter((t) => t.identify && t.identify(obj) || t.class && obj instanceof t.class);
        tagObj = match.find((t) => t.format === item.format) || match.find((t) => !t.format);
      } else {
        obj = item;
        tagObj = tags.find((t) => t.nodeClass && obj instanceof t.nodeClass);
      }
      if (!tagObj) {
        const name = obj && obj.constructor ? obj.constructor.name : typeof obj;
        throw new Error(`Tag not resolved for ${name} value`);
      }
      return tagObj;
    }
    function stringifyProps(node, tagObj, {
      anchors,
      doc
    }) {
      const props = [];
      const anchor = doc.anchors.getName(node);
      if (anchor) {
        anchors[anchor] = node;
        props.push(`&${anchor}`);
      }
      if (node.tag) {
        props.push(stringifyTag(doc, node.tag));
      } else if (!tagObj.default) {
        props.push(stringifyTag(doc, tagObj.tag));
      }
      return props.join(" ");
    }
    function stringify(item, ctx, onComment, onChompKeep) {
      const {
        anchors,
        schema
      } = ctx.doc;
      let tagObj;
      if (!(item instanceof resolveSeq.Node)) {
        const createCtx = {
          aliasNodes: [],
          onTagObj: (o) => tagObj = o,
          prevObjects: /* @__PURE__ */ new Map()
        };
        item = schema.createNode(item, true, null, createCtx);
        for (const alias of createCtx.aliasNodes) {
          alias.source = alias.source.node;
          let name = anchors.getName(alias.source);
          if (!name) {
            name = anchors.newName();
            anchors.map[name] = alias.source;
          }
        }
      }
      if (item instanceof resolveSeq.Pair)
        return item.toString(ctx, onComment, onChompKeep);
      if (!tagObj)
        tagObj = getTagObject(schema.tags, item);
      const props = stringifyProps(item, tagObj, ctx);
      if (props.length > 0)
        ctx.indentAtStart = (ctx.indentAtStart || 0) + props.length + 1;
      const str = typeof tagObj.stringify === "function" ? tagObj.stringify(item, ctx, onComment, onChompKeep) : item instanceof resolveSeq.Scalar ? resolveSeq.stringifyString(item, ctx, onComment, onChompKeep) : item.toString(ctx, onComment, onChompKeep);
      if (!props)
        return str;
      return item instanceof resolveSeq.Scalar || str[0] === "{" || str[0] === "[" ? `${props} ${str}` : `${props}
${ctx.indent}${str}`;
    }
    var Anchors = class _Anchors {
      static validAnchorNode(node) {
        return node instanceof resolveSeq.Scalar || node instanceof resolveSeq.YAMLSeq || node instanceof resolveSeq.YAMLMap;
      }
      constructor(prefix) {
        PlainValue._defineProperty(this, "map", /* @__PURE__ */ Object.create(null));
        this.prefix = prefix;
      }
      createAlias(node, name) {
        this.setAnchor(node, name);
        return new resolveSeq.Alias(node);
      }
      createMergePair(...sources) {
        const merge = new resolveSeq.Merge();
        merge.value.items = sources.map((s) => {
          if (s instanceof resolveSeq.Alias) {
            if (s.source instanceof resolveSeq.YAMLMap)
              return s;
          } else if (s instanceof resolveSeq.YAMLMap) {
            return this.createAlias(s);
          }
          throw new Error("Merge sources must be Map nodes or their Aliases");
        });
        return merge;
      }
      getName(node) {
        const {
          map
        } = this;
        return Object.keys(map).find((a) => map[a] === node);
      }
      getNames() {
        return Object.keys(this.map);
      }
      getNode(name) {
        return this.map[name];
      }
      newName(prefix) {
        if (!prefix)
          prefix = this.prefix;
        const names = Object.keys(this.map);
        for (let i = 1; true; ++i) {
          const name = `${prefix}${i}`;
          if (!names.includes(name))
            return name;
        }
      }
      // During parsing, map & aliases contain CST nodes
      resolveNodes() {
        const {
          map,
          _cstAliases
        } = this;
        Object.keys(map).forEach((a) => {
          map[a] = map[a].resolved;
        });
        _cstAliases.forEach((a) => {
          a.source = a.source.resolved;
        });
        delete this._cstAliases;
      }
      setAnchor(node, name) {
        if (node != null && !_Anchors.validAnchorNode(node)) {
          throw new Error("Anchors may only be set for Scalar, Seq and Map nodes");
        }
        if (name && /[\x00-\x19\s,[\]{}]/.test(name)) {
          throw new Error("Anchor names must not contain whitespace or control characters");
        }
        const {
          map
        } = this;
        const prev = node && Object.keys(map).find((a) => map[a] === node);
        if (prev) {
          if (!name) {
            return prev;
          } else if (prev !== name) {
            delete map[prev];
            map[name] = node;
          }
        } else {
          if (!name) {
            if (!node)
              return null;
            name = this.newName();
          }
          map[name] = node;
        }
        return name;
      }
    };
    var visit = (node, tags) => {
      if (node && typeof node === "object") {
        const {
          tag
        } = node;
        if (node instanceof resolveSeq.Collection) {
          if (tag)
            tags[tag] = true;
          node.items.forEach((n) => visit(n, tags));
        } else if (node instanceof resolveSeq.Pair) {
          visit(node.key, tags);
          visit(node.value, tags);
        } else if (node instanceof resolveSeq.Scalar) {
          if (tag)
            tags[tag] = true;
        }
      }
      return tags;
    };
    var listTagNames = (node) => Object.keys(visit(node, {}));
    function parseContents(doc, contents) {
      const comments = {
        before: [],
        after: []
      };
      let body = void 0;
      let spaceBefore = false;
      for (const node of contents) {
        if (node.valueRange) {
          if (body !== void 0) {
            const msg = "Document contains trailing content not separated by a ... or --- line";
            doc.errors.push(new PlainValue.YAMLSyntaxError(node, msg));
            break;
          }
          const res = resolveSeq.resolveNode(doc, node);
          if (spaceBefore) {
            res.spaceBefore = true;
            spaceBefore = false;
          }
          body = res;
        } else if (node.comment !== null) {
          const cc = body === void 0 ? comments.before : comments.after;
          cc.push(node.comment);
        } else if (node.type === PlainValue.Type.BLANK_LINE) {
          spaceBefore = true;
          if (body === void 0 && comments.before.length > 0 && !doc.commentBefore) {
            doc.commentBefore = comments.before.join("\n");
            comments.before = [];
          }
        }
      }
      doc.contents = body || null;
      if (!body) {
        doc.comment = comments.before.concat(comments.after).join("\n") || null;
      } else {
        const cb = comments.before.join("\n");
        if (cb) {
          const cbNode = body instanceof resolveSeq.Collection && body.items[0] ? body.items[0] : body;
          cbNode.commentBefore = cbNode.commentBefore ? `${cb}
${cbNode.commentBefore}` : cb;
        }
        doc.comment = comments.after.join("\n") || null;
      }
    }
    function resolveTagDirective({
      tagPrefixes
    }, directive) {
      const [handle, prefix] = directive.parameters;
      if (!handle || !prefix) {
        const msg = "Insufficient parameters given for %TAG directive";
        throw new PlainValue.YAMLSemanticError(directive, msg);
      }
      if (tagPrefixes.some((p) => p.handle === handle)) {
        const msg = "The %TAG directive must only be given at most once per handle in the same document.";
        throw new PlainValue.YAMLSemanticError(directive, msg);
      }
      return {
        handle,
        prefix
      };
    }
    function resolveYamlDirective(doc, directive) {
      let [version] = directive.parameters;
      if (directive.name === "YAML:1.0")
        version = "1.0";
      if (!version) {
        const msg = "Insufficient parameters given for %YAML directive";
        throw new PlainValue.YAMLSemanticError(directive, msg);
      }
      if (!documentOptions[version]) {
        const v0 = doc.version || doc.options.version;
        const msg = `Document will be parsed as YAML ${v0} rather than YAML ${version}`;
        doc.warnings.push(new PlainValue.YAMLWarning(directive, msg));
      }
      return version;
    }
    function parseDirectives(doc, directives, prevDoc) {
      const directiveComments = [];
      let hasDirectives = false;
      for (const directive of directives) {
        const {
          comment,
          name
        } = directive;
        switch (name) {
          case "TAG":
            try {
              doc.tagPrefixes.push(resolveTagDirective(doc, directive));
            } catch (error) {
              doc.errors.push(error);
            }
            hasDirectives = true;
            break;
          case "YAML":
          case "YAML:1.0":
            if (doc.version) {
              const msg = "The %YAML directive must only be given at most once per document.";
              doc.errors.push(new PlainValue.YAMLSemanticError(directive, msg));
            }
            try {
              doc.version = resolveYamlDirective(doc, directive);
            } catch (error) {
              doc.errors.push(error);
            }
            hasDirectives = true;
            break;
          default:
            if (name) {
              const msg = `YAML only supports %TAG and %YAML directives, and not %${name}`;
              doc.warnings.push(new PlainValue.YAMLWarning(directive, msg));
            }
        }
        if (comment)
          directiveComments.push(comment);
      }
      if (prevDoc && !hasDirectives && "1.1" === (doc.version || prevDoc.version || doc.options.version)) {
        const copyTagPrefix = ({
          handle,
          prefix
        }) => ({
          handle,
          prefix
        });
        doc.tagPrefixes = prevDoc.tagPrefixes.map(copyTagPrefix);
        doc.version = prevDoc.version;
      }
      doc.commentBefore = directiveComments.join("\n") || null;
    }
    function assertCollection(contents) {
      if (contents instanceof resolveSeq.Collection)
        return true;
      throw new Error("Expected a YAML collection as document contents");
    }
    var Document = class _Document {
      constructor(options) {
        this.anchors = new Anchors(options.anchorPrefix);
        this.commentBefore = null;
        this.comment = null;
        this.contents = null;
        this.directivesEndMarker = null;
        this.errors = [];
        this.options = options;
        this.schema = null;
        this.tagPrefixes = [];
        this.version = null;
        this.warnings = [];
      }
      add(value) {
        assertCollection(this.contents);
        return this.contents.add(value);
      }
      addIn(path, value) {
        assertCollection(this.contents);
        this.contents.addIn(path, value);
      }
      delete(key) {
        assertCollection(this.contents);
        return this.contents.delete(key);
      }
      deleteIn(path) {
        if (resolveSeq.isEmptyPath(path)) {
          if (this.contents == null)
            return false;
          this.contents = null;
          return true;
        }
        assertCollection(this.contents);
        return this.contents.deleteIn(path);
      }
      getDefaults() {
        return _Document.defaults[this.version] || _Document.defaults[this.options.version] || {};
      }
      get(key, keepScalar) {
        return this.contents instanceof resolveSeq.Collection ? this.contents.get(key, keepScalar) : void 0;
      }
      getIn(path, keepScalar) {
        if (resolveSeq.isEmptyPath(path))
          return !keepScalar && this.contents instanceof resolveSeq.Scalar ? this.contents.value : this.contents;
        return this.contents instanceof resolveSeq.Collection ? this.contents.getIn(path, keepScalar) : void 0;
      }
      has(key) {
        return this.contents instanceof resolveSeq.Collection ? this.contents.has(key) : false;
      }
      hasIn(path) {
        if (resolveSeq.isEmptyPath(path))
          return this.contents !== void 0;
        return this.contents instanceof resolveSeq.Collection ? this.contents.hasIn(path) : false;
      }
      set(key, value) {
        assertCollection(this.contents);
        this.contents.set(key, value);
      }
      setIn(path, value) {
        if (resolveSeq.isEmptyPath(path))
          this.contents = value;
        else {
          assertCollection(this.contents);
          this.contents.setIn(path, value);
        }
      }
      setSchema(id, customTags) {
        if (!id && !customTags && this.schema)
          return;
        if (typeof id === "number")
          id = id.toFixed(1);
        if (id === "1.0" || id === "1.1" || id === "1.2") {
          if (this.version)
            this.version = id;
          else
            this.options.version = id;
          delete this.options.schema;
        } else if (id && typeof id === "string") {
          this.options.schema = id;
        }
        if (Array.isArray(customTags))
          this.options.customTags = customTags;
        const opt = Object.assign({}, this.getDefaults(), this.options);
        this.schema = new Schema.Schema(opt);
      }
      parse(node, prevDoc) {
        if (this.options.keepCstNodes)
          this.cstNode = node;
        if (this.options.keepNodeTypes)
          this.type = "DOCUMENT";
        const {
          directives = [],
          contents = [],
          directivesEndMarker,
          error,
          valueRange
        } = node;
        if (error) {
          if (!error.source)
            error.source = this;
          this.errors.push(error);
        }
        parseDirectives(this, directives, prevDoc);
        if (directivesEndMarker)
          this.directivesEndMarker = true;
        this.range = valueRange ? [valueRange.start, valueRange.end] : null;
        this.setSchema();
        this.anchors._cstAliases = [];
        parseContents(this, contents);
        this.anchors.resolveNodes();
        if (this.options.prettyErrors) {
          for (const error2 of this.errors)
            if (error2 instanceof PlainValue.YAMLError)
              error2.makePretty();
          for (const warn of this.warnings)
            if (warn instanceof PlainValue.YAMLError)
              warn.makePretty();
        }
        return this;
      }
      listNonDefaultTags() {
        return listTagNames(this.contents).filter((t) => t.indexOf(Schema.Schema.defaultPrefix) !== 0);
      }
      setTagPrefix(handle, prefix) {
        if (handle[0] !== "!" || handle[handle.length - 1] !== "!")
          throw new Error("Handle must start and end with !");
        if (prefix) {
          const prev = this.tagPrefixes.find((p) => p.handle === handle);
          if (prev)
            prev.prefix = prefix;
          else
            this.tagPrefixes.push({
              handle,
              prefix
            });
        } else {
          this.tagPrefixes = this.tagPrefixes.filter((p) => p.handle !== handle);
        }
      }
      toJSON(arg, onAnchor) {
        const {
          keepBlobsInJSON,
          mapAsMap,
          maxAliasCount
        } = this.options;
        const keep = keepBlobsInJSON && (typeof arg !== "string" || !(this.contents instanceof resolveSeq.Scalar));
        const ctx = {
          doc: this,
          indentStep: "  ",
          keep,
          mapAsMap: keep && !!mapAsMap,
          maxAliasCount,
          stringify
          // Requiring directly in Pair would create circular dependencies
        };
        const anchorNames = Object.keys(this.anchors.map);
        if (anchorNames.length > 0)
          ctx.anchors = new Map(anchorNames.map((name) => [this.anchors.map[name], {
            alias: [],
            aliasCount: 0,
            count: 1
          }]));
        const res = resolveSeq.toJSON(this.contents, arg, ctx);
        if (typeof onAnchor === "function" && ctx.anchors)
          for (const {
            count,
            res: res2
          } of ctx.anchors.values())
            onAnchor(res2, count);
        return res;
      }
      toString() {
        if (this.errors.length > 0)
          throw new Error("Document with errors cannot be stringified");
        const indentSize = this.options.indent;
        if (!Number.isInteger(indentSize) || indentSize <= 0) {
          const s = JSON.stringify(indentSize);
          throw new Error(`"indent" option must be a positive integer, not ${s}`);
        }
        this.setSchema();
        const lines = [];
        let hasDirectives = false;
        if (this.version) {
          let vd = "%YAML 1.2";
          if (this.schema.name === "yaml-1.1") {
            if (this.version === "1.0")
              vd = "%YAML:1.0";
            else if (this.version === "1.1")
              vd = "%YAML 1.1";
          }
          lines.push(vd);
          hasDirectives = true;
        }
        const tagNames = this.listNonDefaultTags();
        this.tagPrefixes.forEach(({
          handle,
          prefix
        }) => {
          if (tagNames.some((t) => t.indexOf(prefix) === 0)) {
            lines.push(`%TAG ${handle} ${prefix}`);
            hasDirectives = true;
          }
        });
        if (hasDirectives || this.directivesEndMarker)
          lines.push("---");
        if (this.commentBefore) {
          if (hasDirectives || !this.directivesEndMarker)
            lines.unshift("");
          lines.unshift(this.commentBefore.replace(/^/gm, "#"));
        }
        const ctx = {
          anchors: /* @__PURE__ */ Object.create(null),
          doc: this,
          indent: "",
          indentStep: " ".repeat(indentSize),
          stringify
          // Requiring directly in nodes would create circular dependencies
        };
        let chompKeep = false;
        let contentComment = null;
        if (this.contents) {
          if (this.contents instanceof resolveSeq.Node) {
            if (this.contents.spaceBefore && (hasDirectives || this.directivesEndMarker))
              lines.push("");
            if (this.contents.commentBefore)
              lines.push(this.contents.commentBefore.replace(/^/gm, "#"));
            ctx.forceBlockIndent = !!this.comment;
            contentComment = this.contents.comment;
          }
          const onChompKeep = contentComment ? null : () => chompKeep = true;
          const body = stringify(this.contents, ctx, () => contentComment = null, onChompKeep);
          lines.push(resolveSeq.addComment(body, "", contentComment));
        } else if (this.contents !== void 0) {
          lines.push(stringify(this.contents, ctx));
        }
        if (this.comment) {
          if ((!chompKeep || contentComment) && lines[lines.length - 1] !== "")
            lines.push("");
          lines.push(this.comment.replace(/^/gm, "#"));
        }
        return lines.join("\n") + "\n";
      }
    };
    PlainValue._defineProperty(Document, "defaults", documentOptions);
    exports.Document = Document;
    exports.defaultOptions = defaultOptions;
    exports.scalarOptions = scalarOptions;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/index.js
var require_dist = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/dist/index.js"(exports) {
    "use strict";
    var parseCst = require_parse_cst();
    var Document$1 = require_Document_a8d0fbf9();
    var Schema = require_Schema_bcc6c2d7();
    var PlainValue = require_PlainValue_516d5bc2();
    var warnings = require_warnings_793925ce();
    require_resolveSeq_95613e94();
    function createNode(value, wrapScalars = true, tag) {
      if (tag === void 0 && typeof wrapScalars === "string") {
        tag = wrapScalars;
        wrapScalars = true;
      }
      const options = Object.assign({}, Document$1.Document.defaults[Document$1.defaultOptions.version], Document$1.defaultOptions);
      const schema = new Schema.Schema(options);
      return schema.createNode(value, wrapScalars, tag);
    }
    var Document = class extends Document$1.Document {
      constructor(options) {
        super(Object.assign({}, Document$1.defaultOptions, options));
      }
    };
    function parseAllDocuments(src, options) {
      const stream = [];
      let prev;
      for (const cstDoc of parseCst.parse(src)) {
        const doc = new Document(options);
        doc.parse(cstDoc, prev);
        stream.push(doc);
        prev = doc;
      }
      return stream;
    }
    function parseDocument(src, options) {
      const cst = parseCst.parse(src);
      const doc = new Document(options).parse(cst[0]);
      if (cst.length > 1) {
        const errMsg = "Source contains multiple documents; please use YAML.parseAllDocuments()";
        doc.errors.unshift(new PlainValue.YAMLSemanticError(cst[1], errMsg));
      }
      return doc;
    }
    function parse(src, options) {
      const doc = parseDocument(src, options);
      doc.warnings.forEach((warning) => warnings.warn(warning));
      if (doc.errors.length > 0)
        throw doc.errors[0];
      return doc.toJSON();
    }
    function stringify(value, options) {
      const doc = new Document(options);
      doc.contents = value;
      return String(doc);
    }
    var YAML = {
      createNode,
      defaultOptions: Document$1.defaultOptions,
      Document,
      parse,
      parseAllDocuments,
      parseCST: parseCst.parse,
      parseDocument,
      scalarOptions: Document$1.scalarOptions,
      stringify
    };
    exports.YAML = YAML;
  }
});

// ../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/index.js
var require_yaml = __commonJS({
  "../../node_modules/.pnpm/yaml@1.10.3/node_modules/yaml/index.js"(exports, module) {
    module.exports = require_dist().YAML;
  }
});

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/yaml.js
var require_yaml2 = __commonJS({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/yaml.js"(exports, module) {
    var yaml = require_yaml();
    var errors = /* @__PURE__ */ new Set([
      "YAMLReferenceError",
      "YAMLSemanticError",
      "YAMLSyntaxError",
      "YAMLWarning"
    ]);
    function parse(str) {
      if (typeof str !== "string") {
        return { ok: false, result: void 0 };
      }
      const YAML_SILENCE_WARNINGS_CACHED = global.YAML_SILENCE_WARNINGS;
      try {
        global.YAML_SILENCE_WARNINGS = true;
        return { ok: true, result: yaml.parse(str) };
      } catch (err) {
        if (err && errors.has(err.name)) {
          return { ok: false, result: void 0 };
        }
        throw err;
      } finally {
        global.YAML_SILENCE_WARNINGS = YAML_SILENCE_WARNINGS_CACHED;
      }
    }
    module.exports = {
      // is_valid is expected to return nothing if input is invalid otherwise
      // true/false for it being valid YAML.
      "yaml.is_valid": (str) => typeof str === "string" ? parse(str).ok : void 0,
      "yaml.marshal": (data) => yaml.stringify(data),
      "yaml.unmarshal": (str) => parse(str).result
    };
  }
});

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/index.js
var require_builtins = __commonJS({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/builtins/index.js"(exports, module) {
    var json = require_json();
    var strings = require_strings();
    var regex = require_regex();
    var yaml = require_yaml2();
    module.exports = {
      ...json,
      ...strings,
      ...regex,
      ...yaml
    };
  }
});

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/opa.js
var require_opa = __commonJS({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/opa.js"(exports, module) {
    var builtIns = require_builtins();
    function stringDecoder(mem) {
      return function(addr) {
        const i8 = new Int8Array(mem.buffer);
        let s = "";
        while (i8[addr] !== 0) {
          s += String.fromCharCode(i8[addr++]);
        }
        return s;
      };
    }
    function _loadJSON(wasmInstance, memory, value) {
      if (value === void 0) {
        return 0;
      }
      let valueBuf;
      if (value instanceof ArrayBuffer) {
        valueBuf = new Uint8Array(value);
      } else {
        const valueAsText = JSON.stringify(value);
        valueBuf = new TextEncoder().encode(valueAsText);
      }
      const valueBufLen = valueBuf.byteLength;
      const rawAddr = wasmInstance.exports.opa_malloc(valueBufLen);
      const memoryBuffer = new Uint8Array(memory.buffer);
      memoryBuffer.set(valueBuf, rawAddr);
      const parsedAddr = wasmInstance.exports.opa_json_parse(rawAddr, valueBufLen);
      if (parsedAddr === 0) {
        throw "failed to parse json value";
      }
      return parsedAddr;
    }
    function _dumpJSON(wasmInstance, memory, addr) {
      const rawAddr = wasmInstance.exports.opa_json_dump(addr);
      return _dumpJSONRaw(memory, rawAddr);
    }
    function _dumpJSONRaw(memory, addr) {
      const buf = new Uint8Array(memory.buffer);
      let idx = addr;
      while (buf[idx] !== 0) {
        idx++;
      }
      const utf8View = new Uint8Array(memory.buffer, addr, idx - addr);
      const jsonAsText = new TextDecoder().decode(utf8View);
      return JSON.parse(jsonAsText);
    }
    var builtinFuncs = builtIns;
    function _builtinCall(wasmInstance, memory, builtins, customBuiltins, builtinId) {
      const builtInName = builtins[builtinId];
      const impl = builtinFuncs[builtInName] || customBuiltins[builtInName];
      if (impl === void 0) {
        throw {
          message: "not implemented: built-in function " + builtinId + ": " + builtins[builtinId]
        };
      }
      const argArray = Array.prototype.slice.apply(arguments);
      const args = [];
      for (let i = 5; i < argArray.length; i++) {
        const jsArg = _dumpJSON(wasmInstance, memory, argArray[i]);
        args.push(jsArg);
      }
      const result = impl(...args);
      return _loadJSON(wasmInstance, memory, result);
    }
    function _importObject(env, memory, customBuiltins) {
      const addr2string = stringDecoder(memory);
      return {
        env: {
          memory,
          opa_abort: function(addr) {
            throw addr2string(addr);
          },
          opa_println: function(addr) {
            console.log(addr2string(addr));
          },
          opa_builtin0: function(builtinId, _ctx) {
            return _builtinCall(
              env.instance,
              memory,
              env.builtins,
              customBuiltins,
              builtinId
            );
          },
          opa_builtin1: function(builtinId, _ctx, arg1) {
            return _builtinCall(
              env.instance,
              memory,
              env.builtins,
              customBuiltins,
              builtinId,
              arg1
            );
          },
          opa_builtin2: function(builtinId, _ctx, arg1, arg2) {
            return _builtinCall(
              env.instance,
              memory,
              env.builtins,
              customBuiltins,
              builtinId,
              arg1,
              arg2
            );
          },
          opa_builtin3: function(builtinId, _ctx, arg1, arg2, arg3) {
            return _builtinCall(
              env.instance,
              memory,
              env.builtins,
              customBuiltins,
              builtinId,
              arg1,
              arg2,
              arg3
            );
          },
          opa_builtin4: function(builtinId, _ctx, arg1, arg2, arg3, arg4) {
            return _builtinCall(
              env.instance,
              memory,
              env.builtins,
              customBuiltins,
              builtinId,
              arg1,
              arg2,
              arg3,
              arg4
            );
          }
        }
      };
    }
    function _preparePolicy(env, wasm, memory) {
      env.instance = wasm.instance ? wasm.instance : wasm;
      const abiVersionGlobal = env.instance.exports.opa_wasm_abi_version;
      if (abiVersionGlobal !== void 0) {
        const abiVersion = typeof abiVersionGlobal === "number" ? abiVersionGlobal : abiVersionGlobal.value;
        if (abiVersion !== 1) {
          throw `unsupported ABI version ${abiVersion}`;
        }
      } else {
        console.error("opa_wasm_abi_version undefined");
      }
      const abiMinorVersionGlobal = env.instance.exports.opa_wasm_abi_minor_version;
      let abiMinorVersion;
      if (abiMinorVersionGlobal !== void 0) {
        abiMinorVersion = typeof abiMinorVersionGlobal === "number" ? abiMinorVersionGlobal : abiMinorVersionGlobal.value;
      } else {
        console.error("opa_wasm_abi_minor_version undefined");
      }
      const builtins = _dumpJSON(
        env.instance,
        memory,
        env.instance.exports.builtins()
      );
      env.builtins = {};
      for (const key of Object.keys(builtins)) {
        env.builtins[builtins[key]] = key;
      }
      return { policy: wasm, minorVersion: abiMinorVersion };
    }
    async function _loadPolicy(policyWasm, memory, customBuiltins) {
      const env = {};
      const isStreaming = policyWasm instanceof Response || policyWasm instanceof Promise;
      const importObject = _importObject(env, memory, customBuiltins);
      const wasm = await (isStreaming ? WebAssembly.instantiateStreaming(policyWasm, importObject) : WebAssembly.instantiate(policyWasm, importObject));
      return _preparePolicy(env, wasm, memory);
    }
    function _loadPolicySync(policyWasm, memory, customBuiltins) {
      const env = {};
      if (policyWasm instanceof ArrayBuffer || policyWasm.buffer instanceof ArrayBuffer) {
        policyWasm = new WebAssembly.Module(policyWasm);
      }
      const wasm = new WebAssembly.Instance(
        policyWasm,
        _importObject(env, memory, customBuiltins)
      );
      return _preparePolicy(env, wasm, memory);
    }
    var LoadedPolicy = class {
      /**
       * Loads and initializes a compiled Rego policy.
       * @param {WebAssembly.WebAssemblyInstantiatedSource} policy
       * @param {WebAssembly.Memory} memory
       */
      constructor(policy, memory, minorVersion) {
        this.minorVersion = minorVersion;
        this.mem = memory;
        this.wasmInstance = policy.instance ? policy.instance : policy;
        this.dataAddr = _loadJSON(this.wasmInstance, this.mem, {});
        this.baseHeapPtr = this.wasmInstance.exports.opa_heap_ptr_get();
        this.dataHeapPtr = this.baseHeapPtr;
        this.entrypoints = _dumpJSON(
          this.wasmInstance,
          this.mem,
          this.wasmInstance.exports.entrypoints()
        );
      }
      /**
       * Evaluates the loaded policy with the given input and
       * return the result set. This should be re-used for multiple evaluations
       * of the same policy with different inputs.
       *
       * To call a non-default entrypoint in your WASM specify it as the second
       * param. A list of entrypoints can be accessed with the `this.entrypoints`
       * property.
       * @param {any | ArrayBuffer} input input to be evaluated in form of `object`, literal primitive or ArrayBuffer (last is assumed to be a well-formed stringified JSON)
       * @param {number | string} entrypoint ID or name of the entrypoint to call (optional)
       */
      evaluate(input2, entrypoint = 0) {
        if (typeof entrypoint === "number") {
        } else if (typeof entrypoint === "string") {
          if (Object.prototype.hasOwnProperty.call(this.entrypoints, entrypoint)) {
            entrypoint = this.entrypoints[entrypoint];
          } else {
            throw `entrypoint ${entrypoint} is not valid in this instance`;
          }
        } else {
          throw `entrypoint value is an invalid type, must be either string or number`;
        }
        if (this.minorVersion >= 2) {
          let inputBuf = null;
          let inputLen = 0;
          let inputAddr2 = 0;
          if (input2) {
            if (input2 instanceof ArrayBuffer) {
              inputBuf = new Uint8Array(input2);
            } else {
              const inputAsText = JSON.stringify(input2);
              inputBuf = new TextEncoder().encode(inputAsText);
            }
            inputAddr2 = this.dataHeapPtr;
            inputLen = inputBuf.byteLength;
            const delta = inputAddr2 + inputLen - this.mem.buffer.byteLength;
            if (delta > 0) {
              const pages = roundup(delta);
              this.mem.grow(pages);
            }
            const buf = new Uint8Array(this.mem.buffer);
            buf.set(inputBuf, this.dataHeapPtr);
          }
          const heapPtr = this.dataHeapPtr + inputLen;
          const ret = this.wasmInstance.exports.opa_eval(
            0,
            entrypoint,
            this.dataAddr,
            inputAddr2,
            inputLen,
            heapPtr,
            0
          );
          return _dumpJSONRaw(this.mem, ret);
        }
        this.wasmInstance.exports.opa_heap_ptr_set(this.dataHeapPtr);
        const inputAddr = _loadJSON(this.wasmInstance, this.mem, input2);
        const ctxAddr = this.wasmInstance.exports.opa_eval_ctx_new();
        this.wasmInstance.exports.opa_eval_ctx_set_input(ctxAddr, inputAddr);
        this.wasmInstance.exports.opa_eval_ctx_set_data(ctxAddr, this.dataAddr);
        this.wasmInstance.exports.opa_eval_ctx_set_entrypoint(ctxAddr, entrypoint);
        this.wasmInstance.exports.eval(ctxAddr);
        const resultAddr = this.wasmInstance.exports.opa_eval_ctx_get_result(
          ctxAddr
        );
        return _dumpJSON(this.wasmInstance, this.mem, resultAddr);
      }
      /**
       * evalBool will evaluate the policy and return a boolean answer
       * depending on the return code from the policy evaluation.
       * @deprecated Use `evaluate` instead.
       * @param {object} input
       */
      evalBool(input2) {
        const rs = this.evaluate(input2);
        return rs && rs.length === 1 && rs[0] === true;
      }
      /**
       * Loads data for use in subsequent evaluations.
       * @param {object | ArrayBuffer} data  data in form of `object` or ArrayBuffer (last is assumed to be a well-formed stringified JSON)
       */
      setData(data) {
        this.wasmInstance.exports.opa_heap_ptr_set(this.baseHeapPtr);
        this.dataAddr = _loadJSON(this.wasmInstance, this.mem, data);
        this.dataHeapPtr = this.wasmInstance.exports.opa_heap_ptr_get();
      }
    };
    function roundup(bytes) {
      const pageSize = 64 * 1024;
      return Math.ceil(bytes / pageSize);
    }
    module.exports = {
      /**
       * Takes in either an ArrayBuffer or WebAssembly.Module
       * and will return a Promise of a LoadedPolicy object which
       * can be used to evaluate the policy.
       *
       * To set custom memory size specify number of memory pages
       * as second param.
       * Defaults to 5 pages (320KB).
       * @param {BufferSource | WebAssembly.Module | Response | Promise<Response>} regoWasm
       * @param {number | WebAssembly.MemoryDescriptor} memoryDescriptor For backwards-compatibility, a 'number' argument is taken to be the initial memory size.
       * @param {{ [builtinName: string]: Function }} customBuiltins A map from string names to builtin functions
       * @returns {Promise<LoadedPolicy>}
       */
      async loadPolicy(regoWasm, memoryDescriptor = {}, customBuiltins = {}) {
        if (typeof memoryDescriptor === "number") {
          memoryDescriptor = { initial: memoryDescriptor };
        }
        memoryDescriptor.initial = memoryDescriptor.initial || 5;
        const memory = new WebAssembly.Memory(memoryDescriptor);
        const { policy, minorVersion } = await _loadPolicy(
          regoWasm,
          memory,
          customBuiltins
        );
        return new LoadedPolicy(policy, memory, minorVersion);
      },
      /**
       * Takes in either an ArrayBuffer or WebAssembly.Module
       * and will return a LoadedPolicy object which can be
       * used to evaluate the policy.
       *
       * This cannot be used from the main thread in a browser.
       * You must use the `loadPolicy` function instead, or call
       * from a worker thread.
       *
       * To set custom memory size specify number of memory pages
       * as second param.
       * Defaults to 5 pages (320KB).
       * @param {BufferSource | WebAssembly.Module} regoWasm
       * @param {number | WebAssembly.MemoryDescriptor} memoryDescriptor For backwards-compatibility, a 'number' argument is taken to be the initial memory size.
       * @param {{ [builtinName: string]: Function }} customBuiltins A map from string names to builtin functions
       * @returns {LoadedPolicy}
       */
      loadPolicySync(regoWasm, memoryDescriptor = {}, customBuiltins = {}) {
        if (typeof memoryDescriptor === "number") {
          memoryDescriptor = { initial: memoryDescriptor };
        }
        memoryDescriptor.initial = memoryDescriptor.initial || 5;
        const memory = new WebAssembly.Memory(memoryDescriptor);
        const { policy, minorVersion } = _loadPolicySync(
          regoWasm,
          memory,
          customBuiltins
        );
        return new LoadedPolicy(policy, memory, minorVersion);
      },
      LoadedPolicy
    };
  }
});

// ../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/index.mjs
var src_exports = {};
__export(src_exports, {
  default: () => src_default,
  loadPolicy: () => loadPolicy
});
var import_opa, loadPolicy, src_default;
var init_src = __esm({
  "../../node_modules/.pnpm/@open-policy-agent+opa-wasm@1.10.0/node_modules/@open-policy-agent/opa-wasm/src/index.mjs"() {
    import_opa = __toESM(require_opa(), 1);
    loadPolicy = import_opa.default.loadPolicy;
    src_default = import_opa.default;
  }
});

// hooks/guard.mjs
import { readFileSync, existsSync, statSync, readdirSync, writeFileSync, mkdirSync, chmodSync, renameSync, appendFileSync, rmSync, rmdirSync, openSync, readSync, closeSync, accessSync, constants } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { resolve, join, dirname, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { createRequire } from "node:module";
import { gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
function projectKey(dir) {
  let h = 2166136261;
  const s = String(dir || "");
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h.toString(16);
}
function projectFlagDir() {
  return join(resolve(homedir(), ".solongate"), "projects", projectKey(resolve(process.cwd())));
}
var _legacySwept = false;
function sweepLegacyFlagDir() {
  if (_legacySwept)
    return;
  _legacySwept = true;
  try {
    const dir = resolve(process.cwd(), ".solongate");
    if (!existsSync(dir))
      return;
    const ours = /* @__PURE__ */ new Set([".eval-ring.jsonl", ".last-eval", ".last-deny", ".last-tool-call", ".debug-guard-log"]);
    const left = [];
    for (const f of readdirSync(dir)) {
      if (ours.has(f)) {
        try {
          rmSync(join(dir, f), { force: true });
        } catch {
          left.push(f);
        }
      } else
        left.push(f);
    }
    if (left.length === 0) {
      try {
        rmdirSync(dir);
      } catch {
      }
    }
  } catch {
  }
}
var HOOK_VERSION = 96;
var SG_DIR_MODE = 448;
var SG_FILE_MODE = 384;
var SG_REFRESH_ARG = process.argv.includes("--sg-refresh-policy");
var SG_STDIN = SG_REFRESH_ARG ? "" : (() => {
  try {
    return readFileSync(0, "utf-8");
  } catch {
    return "";
  }
})();
var SG_ORIGIN_MS = (() => {
  try {
    return Math.round(performance.timeOrigin);
  } catch {
    return Date.now();
  }
})();
function sgGuardCandidates() {
  const out = [];
  if (process.env.SOLONGATE_GUARD_BIN)
    out.push(process.env.SOLONGATE_GUARD_BIN);
  const exe = process.platform === "win32" ? "solongate-guard.exe" : "solongate-guard";
  const os_ = process.platform === "win32" ? "win32" : process.platform;
  const cpu = process.arch === "x64" ? "x64" : process.arch;
  try {
    const req = createRequire(import.meta.url);
    out.push(join(dirname(req.resolve(`@solongate/guard-${os_}-${cpu}/package.json`)), exe));
  } catch {
  }
  out.push(resolve(homedir(), ".solongate", "bin", exe));
  return out;
}
function sgTryGoGuard() {
  for (const bin of sgGuardCandidates()) {
    try {
      if (!existsSync(bin))
        continue;
      if (process.platform !== "win32")
        accessSync(bin, constants.X_OK);
    } catch {
      continue;
    }
    let version;
    try {
      const v = spawnSync(bin, ["--sg-version"], { encoding: "utf-8", timeout: 2e3 });
      if (v.error || v.status !== 0)
        continue;
      version = String(v.stdout || "").trim();
    } catch {
      continue;
    }
    if (version !== String(HOOK_VERSION))
      continue;
    let r;
    try {
      r = spawnSync(bin, process.argv.slice(2), {
        input: SG_STDIN,
        encoding: "utf-8",
        // The binary writes the eval record the audit hook reads back, so it is
        // the one reporting this call's guard time — and from inside a process
        // that was spawned partway through the work, it can only see its own
        // share of it. Node's boot, this file's parse, the fd 0 read and the
        // version probe above are all already spent by the time it starts.
        // Handing it the origin is what lets the number it reports be the whole
        // hook instead of the last two milliseconds of it.
        env: { ...process.env, SOLONGATE_HOOK_ORIGIN_MS: String(SG_ORIGIN_MS) },
        // Well past every network call the guard makes. A binary still running
        // at this point is not going to produce an answer worth waiting for.
        timeout: 1e4
      });
    } catch {
      return;
    }
    if (!r || r.error || r.signal)
      return;
    const status = r.status;
    const stdout = r.stdout || "";
    if (status !== 0 && status !== 2)
      return;
    if (status === 2 && stdout.trim() === "")
      return;
    try {
      if (stdout)
        process.stdout.write(stdout);
      if (r.stderr)
        process.stderr.write(r.stderr);
    } catch {
      return;
    }
    process.exit(status);
  }
}
if (!SG_REFRESH_ARG && process.env.SOLONGATE_NO_GO_GUARD !== "1") {
  try {
    sgTryGoGuard();
  } catch {
  }
}
function loadLocalPolicyFile(cwd) {
  for (const p of [
    join(resolve(homedir(), ".solongate"), "policy.json"),
    cwd ? resolve(cwd, "policy.json") : ""
  ]) {
    if (!p || !existsSync(p))
      continue;
    try {
      const obj = JSON.parse(readFileSync(p, "utf-8"));
      if (!obj || typeof obj !== "object")
        continue;
      const own = !cwd || p !== resolve(cwd, "policy.json");
      const inner = own && obj.policy && typeof obj.policy === "object" ? obj.policy.security : void 0;
      if (obj.policy && typeof obj.policy === "object") {
        return {
          policy: obj.policy,
          security: own && obj.security !== void 0 ? obj.security : inner,
          selfProtect: own && typeof obj.selfProtect === "boolean" ? obj.selfProtect : void 0,
          path: p
        };
      }
      return {
        policy: obj,
        security: own && obj.security !== void 0 ? obj.security : void 0,
        selfProtect: void 0,
        path: p
      };
    } catch {
    }
  }
  return null;
}
function localLogsOnly(security) {
  if (!API_KEY)
    return true;
  if (security !== void 0) {
    const l = security && security.localLogs;
    return !!(l && l.enabled && typeof l.path === "string" && l.path.trim());
  }
  try {
    const m = JSON.parse(readFileSync(join(resolve(homedir(), ".solongate"), ".local-logs-mode.json"), "utf-8"));
    return !!(m && m.localOnly);
  } catch {
    return false;
  }
}
function writeLocalMarker(security) {
  try {
    const l = security && security.localLogs;
    const localOnly = !!(l && l.enabled && typeof l.path === "string" && l.path.trim());
    writeFileSync(join(resolve(homedir(), ".solongate"), ".local-logs-mode.json"), JSON.stringify({ localOnly, ts: Date.now() }));
  } catch {
  }
}
function accountMark() {
  try {
    return API_KEY ? createHash("sha256").update(API_KEY).digest("hex").slice(0, 16) : "";
  } catch {
    return "";
  }
}
function postAuditDetached(entry) {
  if (!API_KEY)
    return;
  try {
    const payload = Buffer.from(JSON.stringify({
      url: API_URL + "/api/v1/audit-logs",
      headers: AUTH_HEADERS,
      body: entry
    }), "utf-8").toString("base64");
    spawn(process.execPath, [process.argv[1], "--sg-audit-post", payload], { detached: true, stdio: "ignore" }).unref();
  } catch {
  }
}
function writeLocalLog(security, entry) {
  try {
    const mark = accountMark();
    if (mark)
      entry = { ...entry, acct: mark };
    const l = security && security.localLogs;
    if (!l || !l.enabled || typeof l.path !== "string" || !l.path.trim()) {
      if (!localLogsOnly(security))
        return;
      const fallbackDir = resolve(homedir(), ".solongate", "local-logs");
      const fallbackLine = JSON.stringify(entry) + "\n";
      const fallbackPayload = Buffer.from(JSON.stringify({ dir: fallbackDir, line: fallbackLine }), "utf-8").toString("base64");
      spawn(process.execPath, [process.argv[1], "--sg-log-write", fallbackPayload], { detached: true, stdio: "ignore" }).unref();
      return;
    }
    let dir = String(l.path).trim().replace(/[\\/]+$/, "");
    if (!dir)
      return;
    if (!isAbsolute(dir))
      dir = resolve(homedir(), ".solongate", "local-logs");
    const line = JSON.stringify(entry) + "\n";
    const payload = Buffer.from(JSON.stringify({ dir, line }), "utf-8").toString("base64");
    spawn(process.execPath, [process.argv[1], "--sg-log-write", payload], { detached: true, stdio: "ignore" }).unref();
  } catch {
  }
}
var MAX_FILE_READ = 1024 * 1024;
function safeReadFileSync(filePath, encoding = "utf-8") {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_READ)
      return "";
    return readFileSync(filePath, encoding);
  } catch {
    return "";
  }
}
function loadEnvKey(dir) {
  try {
    const envPath = resolve(dir, ".env");
    if (!existsSync(envPath))
      return {};
    const lines = readFileSync(envPath, "utf-8").split("\n");
    const env = {};
    for (const line of lines) {
      const m = line.match(/^([A-Z_]+)=(.*)$/);
      if (m)
        env[m[1]] = m[2].replace(/^["']|["']$/g, "").trim();
    }
    return env;
  } catch {
    return {};
  }
}
function loadGlobalCloudConfig() {
  try {
    const p = resolve(homedir(), ".solongate", "cloud-guard.json");
    if (!existsSync(p))
      return {};
    const cfg = JSON.parse(readFileSync(p, "utf-8"));
    return cfg && typeof cfg === "object" ? cfg : {};
  } catch {
    return {};
  }
}
function isRealKey(k) {
  if (typeof k !== "string")
    return false;
  const v = k.trim();
  if (!/^sg_(live|test)_/.test(v))
    return false;
  const body = v.replace(/^sg_(live|test)_/, "");
  if (/your_key_here|placeholder|example|^x+$/i.test(body))
    return false;
  return /^[a-f0-9]{16,}$/i.test(body);
}
function guessPermission(toolName) {
  const name = (toolName || "").toLowerCase();
  if (name === "apply_patch" || name === "applypatch")
    return "WRITE";
  if (name.includes("exec") || name.includes("shell") || name.includes("run") || name.includes("eval") || name === "bash")
    return "EXECUTE";
  if (name.includes("fetch") || name.includes("http") || name.includes("request") || name.includes("curl") || name.includes("network") || name.includes("download") || name.includes("upload") || name === "websearch")
    return "NETWORK";
  if (name.includes("write") || name.includes("create") || name.includes("delete") || name.includes("update") || name.includes("set") || name.includes("edit") || name.includes("remove") || name.includes("insert") || name.includes("replace") || name.includes("patch") || name.includes("modify") || name.includes("append") || name.includes("overwrite") || name.includes("rename") || name.includes("move") || name.includes("mkdir") || name.includes("touch"))
    return "WRITE";
  return "READ";
}
var hookCwdEarly = process.cwd();
var dotenv = loadEnvKey(hookCwdEarly);
var globalCfg = loadGlobalCloudConfig();
var API_URL = process.env.SOLONGATE_API_URL || globalCfg.apiUrl || dotenv.SOLONGATE_API_URL || "http://127.0.0.1:3002";
var API_KEY = [process.env.SOLONGATE_API_KEY, globalCfg.apiKey, dotenv.SOLONGATE_API_KEY].find(isRealKey) || "";
var API_KEY_SOURCE = process.env.SOLONGATE_API_KEY && isRealKey(process.env.SOLONGATE_API_KEY) ? "environment variable SOLONGATE_API_KEY" : isRealKey(globalCfg.apiKey) ? "login (~/.solongate)" : join(hookCwdEarly, ".env");
var API_URL_SOURCE = process.env.SOLONGATE_API_URL ? "environment variable SOLONGATE_API_URL" : globalCfg.apiUrl ? "login (~/.solongate)" : join(hookCwdEarly, ".env");
function noteAuthResult(ok) {
  try {
    const p = join(resolve(homedir(), ".solongate"), ".key-rejected.json");
    if (ok) {
      if (existsSync(p))
        rmSync(p, { force: true });
      return;
    }
    writeFileSync(p, JSON.stringify({
      ts: Date.now(),
      cwd: hookCwdEarly,
      keySource: API_KEY_SOURCE,
      apiUrl: API_URL,
      apiUrlSource: API_URL_SOURCE
    }));
  } catch {
  }
}
var AUTH_HEADERS = API_KEY ? { "Authorization": "Bearer " + API_KEY, "X-API-Key": API_KEY } : {};
async function fetchAndInstallHook(endpoint, fileName, currentVersion, marker, minLen) {
  try {
    const res = await fetch(API_URL + "/api/v1/hooks/" + endpoint, { headers: AUTH_HEADERS, signal: AbortSignal.timeout(5e3) });
    if (!res.ok)
      return;
    const data = await res.json();
    if (!data || typeof data.version !== "number" || data.version <= currentVersion)
      return;
    if (typeof data.content !== "string" || typeof data.sha256 !== "string")
      return;
    const buf = Buffer.from(data.content, "base64");
    if (createHash("sha256").update(buf).digest("hex") !== data.sha256)
      return;
    const text = buf.toString("utf-8");
    if (!text.startsWith("#!/usr/bin/env node") || text.length < minLen || !text.includes(marker))
      return;
    const hooksDir = join(resolve(homedir(), ".solongate"), "hooks");
    const tmp = join(hooksDir, "." + fileName + ".tmp");
    writeFileSync(tmp, text);
    try {
      chmodSync(join(hooksDir, fileName), 420);
    } catch {
    }
    renameSync(tmp, join(hooksDir, fileName));
  } catch {
  }
}
function installedHookVersion(fileName) {
  try {
    const f = join(resolve(homedir(), ".solongate"), "hooks", fileName);
    const m = (safeReadFileSync(f) || "").match(/HOOK_VERSION\s*=\s*(\d+)/);
    return m ? parseInt(m[1], 10) : 0;
  } catch {
    return 0;
  }
}
function registeredClients() {
  const home = resolve(homedir());
  const has = (p, needle) => {
    try {
      const s = safeReadFileSync(p);
      if (!s)
        return false;
      return needle ? s.includes(needle) : true;
    } catch {
      return false;
    }
  };
  const out = [];
  if (has(join(home, ".claude", "settings.json"), ".solongate"))
    out.push("claude-code");
  if (has(join(home, ".gemini", "config", "hooks.json"), ".solongate"))
    out.push("antigravity");
  if (has(join(process.env.CODEX_HOME ? resolve(process.env.CODEX_HOME) : join(home, ".codex"), "hooks.json"), ".solongate"))
    out.push("codex");
  const xdg = process.env.XDG_CONFIG_HOME ? resolve(process.env.XDG_CONFIG_HOME) : join(home, ".config");
  if (has(join(xdg, "opencode", "plugins", "solongate.js"), "tool.execute.before"))
    out.push("opencode");
  return out;
}
var CLOUD_HOOK_VERSIONS = null;
function hooksBehindCloud() {
  const v = CLOUD_HOOK_VERSIONS;
  if (!v || typeof v !== "object")
    return false;
  if (Number(v.guard) > HOOK_VERSION)
    return true;
  if (Number(v.audit) > installedHookVersion("audit.mjs"))
    return true;
  if (Number(v.shield) > installedHookVersion("shield.mjs"))
    return true;
  return false;
}
async function maybeSelfUpdate() {
  if (!API_KEY)
    return;
  try {
    const sgDir = resolve(homedir(), ".solongate");
    const stamp = join(sgDir, ".hook-update-check");
    if (!hooksBehindCloud()) {
      const last = parseInt(safeReadFileSync(stamp) || "0", 10);
      if (Number.isFinite(last) && Date.now() - last < 6 * 3600 * 1e3)
        return;
    }
    try {
      writeFileSync(stamp, String(Date.now()));
    } catch {
    }
    await fetchAndInstallHook("guard", "guard.mjs", HOOK_VERSION, "SolonGate Cloud Policy Guard", 5e4);
    await fetchAndInstallHook("audit", "audit.mjs", installedHookVersion("audit.mjs"), "SolonGate Audit Hook", 1500);
    await fetchAndInstallHook("shield", "shield.mjs", installedHookVersion("shield.mjs"), "SolonGate Shield", 1500);
  } catch {
  }
}
var AGENT_TYPE = process.argv[2] || "claude-code";
var POLICY_SELECTOR = process.env.SOLONGATE_AGENT_ID || "";
var AGENT_ID = POLICY_SELECTOR || AGENT_TYPE;
var AGENT_NAME = process.env.SOLONGATE_AGENT_NAME || process.argv[3] || AGENT_TYPE;
{
  const _ai = process.argv.indexOf("--sg-audit-post");
  if (_ai !== -1) {
    try {
      const _raw = Buffer.from(process.argv[_ai + 1] || "", "base64").toString("utf-8");
      const _p = JSON.parse(_raw);
      if (_p && _p.url && _p.body) {
        fetch(_p.url, {
          method: "POST",
          headers: { "Content-Type": "application/json", ..._p.headers || {} },
          body: JSON.stringify(_p.body),
          signal: AbortSignal.timeout(1e4)
        }).catch(() => {
        }).finally(() => process.exit(0));
        setTimeout(() => process.exit(0), 11e3).unref();
      } else
        process.exit(0);
    } catch {
      process.exit(0);
    }
  }
}
{
  const _wi = process.argv.indexOf("--sg-log-write");
  if (_wi !== -1) {
    try {
      const _pl = JSON.parse(Buffer.from(process.argv[_wi + 1] || "", "base64").toString("utf-8"));
      if (_pl && _pl.dir && _pl.line) {
        let _dir = _pl.dir;
        const _narrow = (f) => {
          try {
            chmodSync(f, SG_FILE_MODE);
          } catch {
          }
        };
        try {
          mkdirSync(_dir, { recursive: true, mode: SG_DIR_MODE });
          const _f = join(_dir, "solongate-audit.jsonl");
          appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
          _narrow(_f);
        } catch {
          const _fb = join(resolve(homedir(), ".solongate"), "local-logs");
          try {
            mkdirSync(_fb, { recursive: true, mode: SG_DIR_MODE });
          } catch {
          }
          try {
            const _f = join(_fb, "solongate-audit.jsonl");
            appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
            _narrow(_f);
          } catch {
          }
          try {
            writeFileSync(
              join(resolve(homedir(), ".solongate"), ".local-logs-invalid-path"),
              JSON.stringify({ configured: _dir, fallback: _fb, ts: Date.now() })
            );
          } catch {
          }
        }
      }
    } catch {
    }
    process.exit(0);
  }
}
var REFRESH_MODE = process.argv.includes("--sg-refresh-policy");
async function refreshPolicyCache() {
  try {
    const agentKey = (AGENT_ID || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
    const cacheFile = join(resolve(homedir(), ".solongate"), ".policy-cache-" + agentKey + ".json");
    let selfProtect = true, security = null, hookVersions = null, policy = null;
    try {
      if (existsSync(cacheFile)) {
        const c = JSON.parse(readFileSync(cacheFile, "utf-8"));
        if (c) {
          policy = c.policy ?? null;
          if (typeof c.selfProtect === "boolean")
            selfProtect = c.selfProtect;
          if (c.security !== void 0)
            security = c.security;
          if (c.hookVersions)
            hookVersions = c.hookVersions;
        }
      }
    } catch {
    }
    try {
      const res = await fetch(
        API_URL + "/api/v1/policies/active?agent_id=" + encodeURIComponent(AGENT_ID || "") + "&hv=" + HOOK_VERSION + "&clients=" + encodeURIComponent(registeredClients().join(",")),
        { headers: AUTH_HEADERS, signal: AbortSignal.timeout(8e3) }
      );
      if (res.ok) {
        const body = await res.json();
        if (typeof body?.self_protection_enabled === "boolean")
          selfProtect = body.self_protection_enabled;
        security = body?.security !== void 0 ? body.security : null;
        if (body?.hook_versions && typeof body.hook_versions === "object")
          hookVersions = body.hook_versions;
        policy = body && body.policy ? body.policy : null;
        noteAuthResult(true);
      } else if (res.status === 401 || res.status === 403) {
        noteAuthResult(false);
      }
    } catch {
    }
    try {
      writeFileSync(cacheFile, JSON.stringify({ _ts: Date.now(), policy, selfProtect, security, hookVersions }));
    } catch {
    }
    writeLocalMarker(security);
  } catch {
  }
}
if (REFRESH_MODE) {
  try {
    setTimeout(() => {
      try {
        process.exit(process.exitCode || 0);
      } catch {
      }
    }, 8e3).unref();
  } catch {
  }
  refreshPolicyCache().finally(() => {
    process.exitCode = 0;
  });
}
var SG_DONE = Symbol("sg-done");
var _sgDone = false;
var _decisionEmitted = false;
function sgFinish(code) {
  if (!_sgDone) {
    _sgDone = true;
    process.exitCode = code;
  }
  throw SG_DONE;
}
var ARG_ALIASES = {
  commandline: "command",
  cmd: "command",
  absolutepath: "file_path",
  targetfile: "file_path",
  filepath: "file_path",
  target_file: "file_path",
  notebook_path: "file_path"
};
function neutralizeArgs(a, drop = []) {
  const out = {};
  for (const [k, v] of Object.entries(a && typeof a === "object" ? a : {})) {
    const lk = k.toLowerCase();
    if (drop.includes(lk))
      continue;
    const nk = ARG_ALIASES[lk] || k;
    if (out[nk] === void 0)
      out[nk] = v;
  }
  return out;
}
function parseFlatPayload(raw) {
  const args = neutralizeArgs(raw.tool_input || raw.toolInput || raw.params || {});
  return {
    tool: raw.tool_name || raw.toolName || "",
    args,
    command: typeof args?.command === "string" ? args.command : null,
    cwd: raw.cwd || "",
    sessionId: raw.session_id || raw.sessionId || raw.conversation_id || "",
    response: raw.tool_response || raw.toolResponse || {}
  };
}
function emitHookSpecific(d) {
  if (d.type === "deny") {
    const msg = d.reason || "[SolonGate] Blocked by policy";
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: msg
      }
    }));
    process.stderr.write(msg + "\n");
    return 2;
  }
  if (d.type === "rewrite") {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: d.patch }
    }));
    return 0;
  }
  return 0;
}
var CLIENTS = {
  "claude-code": {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    redactsOutput: true
    // audit.mjs rewrites the tool result at PostToolUse
  },
  // Codex CLI: same decision dialect as Claude Code, different INPUT problem.
  // Every file edit arrives as one apply_patch call whose target paths live
  // inside the patch text, so parse lifts them onto the neutral `paths` field
  // (see liftFreeformPatchPaths, applied to every client for safety).
  codex: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    redactsOutput: false
    // has a post-tool stage, but it rejects output rewrites
  },
  // OpenCode: no subprocess hook contract at all — a plugin runs in-process and
  // refuses a call by throwing. The shim that does the throwing (see
  // hooks/opencode-plugin.mjs) spawns this guard with a flat Claude-shaped
  // payload and reads the Claude dialect back, so both halves are reused as-is
  // and only the identity differs.
  opencode: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    // tool.execute.after does hand the plugin the tool's result, but whether
    // writing to it changes what the model sees is untested. Claiming the
    // capability we have not proven would let a secret through masked-in-name-
    // only; false makes any masking we cannot apply a block instead.
    redactsOutput: false
  },
  // Antigravity CLI: nested payload, and a decision dialect of its own.
  antigravity: {
    redactsOutput: false,
    // no post-tool stage at all (its output is ignored)
    parse(raw) {
      const tc = raw.toolCall && typeof raw.toolCall === "object" ? raw.toolCall : {};
      const a = tc.args && typeof tc.args === "object" ? tc.args : {};
      const args = neutralizeArgs(a, ["cwd"]);
      let cwd = raw.cwd || "";
      if (!cwd) {
        if (typeof a.Cwd === "string" && a.Cwd)
          cwd = a.Cwd;
        else if (Array.isArray(raw.workspacePaths) && typeof raw.workspacePaths[0] === "string")
          cwd = raw.workspacePaths[0];
      }
      return {
        tool: raw.tool_name || tc.name || "",
        args,
        command: typeof args.command === "string" ? args.command : null,
        cwd,
        sessionId: raw.session_id || raw.conversationId || "",
        response: raw.tool_response || raw.toolResponse || {}
      };
    },
    emit(d) {
      if (d.type === "deny") {
        const msg = `[SolonGate] ${d.reason}`;
        process.stdout.write(JSON.stringify({ decision: "deny", reason: msg, allow_tool: false, deny_reason: msg }));
        return 0;
      }
      if (d.type === "rewrite") {
        const overwrite = {};
        if (d.patch && typeof d.patch.command === "string")
          overwrite.CommandLine = d.patch.command;
        else
          Object.assign(overwrite, d.patch || {});
        process.stdout.write(JSON.stringify({ decision: "allow", overwrite, allow_tool: true }));
        return 0;
      }
      process.stdout.write(JSON.stringify({ decision: "allow", allow_tool: true }));
      return 0;
    }
  },
  // Unknown client: never silently adopt another client's rules. Parse by
  // payload SHAPE and deny with the most widely enforced signal available
  // (JSON + exit 2). A client that needs anything else gets its own entry.
  generic: {
    redactsOutput: false,
    // assume the weaker capability, so masking fails closed
    parse(raw) {
      return raw.toolCall && typeof raw.toolCall === "object" ? CLIENTS.antigravity.parse(raw) : parseFlatPayload(raw);
    },
    emit: emitHookSpecific
  }
};
var CLIENT = CLIENTS[AGENT_TYPE] || CLIENTS.generic;
function emitDecision(d) {
  if (!_decisionEmitted) {
    _decisionEmitted = true;
    const code = CLIENT.emit(d);
    sgFinish(code);
  }
  sgFinish(0);
}
function blockTool(reason) {
  emitDecision({ type: "deny", reason });
}
function allowTool() {
  emitDecision({ type: "allow" });
}
function rewriteTool(patch) {
  emitDecision({ type: "rewrite", patch });
}
var CALL_ID = "";
var CALL_FP = "";
function callFingerprint(s) {
  let h = 2166136261;
  const str = String(s || "");
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h.toString(16);
}
function writeDenyFlag(toolName) {
  try {
    const flagDir = projectFlagDir();
    mkdirSync(flagDir, { recursive: true });
    writeFileSync(join(flagDir, ".last-deny"), JSON.stringify({
      tool: toolName,
      ts: Date.now(),
      id: CALL_ID,
      fp: CALL_FP
    }));
  } catch {
  }
}
function matchGlob(str, pattern) {
  if (pattern === "*")
    return true;
  const s = str.toLowerCase();
  const p = pattern.toLowerCase();
  if (s === p)
    return true;
  const startsW = p.startsWith("*");
  const endsW = p.endsWith("*");
  if (startsW && endsW) {
    const infix = p.slice(1, -1);
    return infix.length > 0 && s.includes(infix);
  }
  if (startsW)
    return s.endsWith(p.slice(1));
  if (endsW)
    return s.startsWith(p.slice(0, -1));
  const idx = p.indexOf("*");
  if (idx !== -1) {
    const pre = p.slice(0, idx);
    const suf = p.slice(idx + 1);
    return s.startsWith(pre) && s.endsWith(suf) && s.length >= pre.length + suf.length;
  }
  return false;
}
function matchPathGlob(path, pattern) {
  const p = path.replace(/\\/g, "/").toLowerCase();
  const g = pattern.replace(/\\/g, "/").toLowerCase();
  if (p === g)
    return true;
  if (g.includes("**")) {
    const parts = g.split("**").filter((s) => s.length > 0);
    if (parts.length === 0)
      return true;
    return parts.every((segment) => p.includes(segment));
  }
  return matchGlob(p, g);
}
function scanStrings(obj) {
  const strings = [];
  function walk(v) {
    if (typeof v === "string" && v.trim())
      strings.push(v.trim());
    else if (Array.isArray(v))
      v.forEach(walk);
    else if (v && typeof v === "object")
      Object.values(v).forEach(walk);
  }
  walk(obj);
  return strings;
}
function looksLikeFilename(s) {
  if (s.startsWith("."))
    return true;
  if (/\.\w+$/.test(s))
    return true;
  const known = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts", "makefile", "dockerfile"];
  return known.includes(s.toLowerCase());
}
function normalizeShellCommand(cmd) {
  if (typeof cmd !== "string" || !cmd)
    return cmd;
  const vars = {};
  const out = [];
  for (const rawPart of cmd.split(/\s*(?:;|&&|\|\|)\s*/)) {
    let part = rawPart;
    const m = part.match(/^(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))\s*$/);
    if (m) {
      vars[m[1]] = m[2] ?? m[3] ?? m[4] ?? "";
      continue;
    }
    part = part.replace(/\$\{(\w+)\}/g, (_, n) => vars[n] !== void 0 ? vars[n] : "${" + n + "}");
    part = part.replace(/\$(\w+)/g, (_, n) => vars[n] !== void 0 ? vars[n] : "$" + n);
    part = part.replace(/"([^"]*)"/g, "$1").replace(/'([^']*)'/g, "$1");
    out.push(part);
  }
  return out.join("; ");
}
function normalizeArgs(args) {
  if (!args || typeof args !== "object")
    return args;
  const fields = ["command", "cmd", "function", "script", "shell"];
  const copy = { ...args };
  for (const [k, v] of Object.entries(copy)) {
    if (fields.includes(k.toLowerCase()) && typeof v === "string") {
      copy[k] = normalizeShellCommand(v);
    }
  }
  return copy;
}
function extractFilenames(args) {
  args = normalizeArgs(args);
  const names = /* @__PURE__ */ new Set();
  const dequote = (t) => t.replace(/^["'`]+/, "").replace(/["'`]+$/, "");
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s))
      continue;
    const tokens = s.includes(" ") ? s.split(/\s+/) : [s];
    const single = tokens.length === 1;
    for (let tok of tokens) {
      tok = dequote(tok);
      if (!tok || /^https?:\/\//i.test(tok))
        continue;
      if (tok.includes("/") || tok.includes("\\")) {
        const b = dequote(tok.replace(/\\/g, "/").split("/").pop() || "");
        if (b && (single || looksLikeFilename(b)))
          names.add(b);
      } else if (looksLikeFilename(tok)) {
        names.add(tok);
      }
    }
  }
  return [...names];
}
function extractUrls(args) {
  const urls = /* @__PURE__ */ new Set();
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) {
      urls.add(s);
      continue;
    }
    if (s.includes(" ")) {
      for (const tok of s.split(/\s+/)) {
        if (/^https?:\/\//i.test(tok))
          urls.add(tok);
      }
    }
  }
  return [...urls];
}
function extractCommands(args) {
  args = normalizeArgs(args);
  const cmds = [];
  const fields = ["command", "cmd", "function", "script", "shell"];
  if (typeof args === "object" && args) {
    for (const [k, v] of Object.entries(args)) {
      if (fields.includes(k.toLowerCase()) && typeof v === "string") {
        for (const part of v.split(/\s*(?:&&|\|\||;|\|)\s*/)) {
          const trimmed = part.trim();
          if (trimmed)
            cmds.push(trimmed);
        }
      }
    }
  }
  return cmds;
}
function extractPaths(args, isExec) {
  const paths = [];
  const add = (t) => {
    if (!t || /^https?:\/\//i.test(t))
      return;
    if (t.includes("/") || t.includes("\\") || t.startsWith("."))
      paths.push(t.replace(/\\/g, "/"));
  };
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s))
      continue;
    if (isExec && /\s/.test(s)) {
      for (const tok of s.split(/[\s;|&><()`'"]+/))
        add(tok);
    } else {
      add(s);
    }
  }
  return paths;
}
var SEARCH_WALK_MAX_FILES = 2e3;
var SEARCH_WALK_MAX_DEPTH = 8;
var SEARCH_SKIP_DIRS = /* @__PURE__ */ new Set([
  ".git",
  "node_modules",
  ".venv",
  "venv",
  "vendor",
  "dist",
  "build",
  "target",
  "__pycache__",
  ".next",
  ".turbo"
]);
function isContentSearchTool(tool) {
  const n = String(tool || "").toLowerCase();
  if (n.includes("websearch") || n.includes("web_search"))
    return false;
  return n.includes("grep") || n.includes("search") || n.includes("ripgrep");
}
function walkSearchRoot(root, budget, depth, out) {
  if (budget.n <= 0 || depth > SEARCH_WALK_MAX_DEPTH)
    return;
  let entries;
  try {
    entries = readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (budget.n <= 0)
      return;
    const p = root + "/" + e.name;
    if (e.isDirectory()) {
      if (SEARCH_SKIP_DIRS.has(e.name))
        continue;
      walkSearchRoot(p, budget, depth + 1, out);
      continue;
    }
    budget.n--;
    out.push(p);
  }
}
function expandSearchRoots(tool, args, cwd) {
  if (!isContentSearchTool(tool) || !args || typeof args !== "object")
    return [];
  const base = cwd || process.cwd();
  const out = [];
  const budget = { n: SEARCH_WALK_MAX_FILES };
  for (const v of scanStrings(args)) {
    if (budget.n <= 0)
      break;
    if (/^https?:\/\//i.test(v) || !/[/\\]/.test(v))
      continue;
    const root = v.startsWith("/") ? v : base + "/" + v;
    try {
      if (!statSync(root).isDirectory())
        continue;
    } catch {
      continue;
    }
    walkSearchRoot(root.replace(/\/+$/, ""), budget, 0, out);
  }
  return out;
}
function expandCommandGlobs(args, cwd) {
  const out = [];
  try {
    const base = cwd || process.cwd();
    for (const cmd of extractCommands(args)) {
      for (const tok of String(cmd).split(/[\s'"|<>;&()]+/)) {
        if (!tok || tok.startsWith("-") || !/[*?\[]/.test(tok) || /^https?:\/\//i.test(tok))
          continue;
        let g = tok;
        if (g.startsWith("~"))
          g = homedir() + g.slice(1);
        let abs;
        try {
          abs = isAbsolute(g) ? g : resolve(base, g);
        } catch {
          continue;
        }
        const dir = dirname(abs), b = abs.slice(dir.length + 1);
        if (!/[*?\[]/.test(b))
          continue;
        let re;
        try {
          re = new RegExp("^" + b.replace(/\*{2,}/g, "*").replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$");
        } catch {
          continue;
        }
        let files;
        try {
          files = readdirSync(dir);
        } catch {
          continue;
        }
        for (const f of files)
          if (re.test(f))
            out.push(join(dir, f).replace(/\\/g, "/"));
      }
    }
  } catch {
  }
  return out;
}
var TAMPER_GUARD_TOOLS_EXEC = /* @__PURE__ */ new Set([
  "bash",
  "powershell",
  "shell",
  "exec",
  "run",
  "eval",
  "cmd"
]);
var TAMPER_HOME = resolve(homedir()).replace(/\\/g, "/").toLowerCase();
var TAMPER_SG = "/.solongate";
var TAMPER_CC = "/.claude";
var TAMPER_CX = "/.codex";
var TAMPER_AGY = "/.gemini/config";
var TAMPER_PROTECTED_ABS = [
  TAMPER_HOME + TAMPER_CC + "/settings.json",
  TAMPER_HOME + TAMPER_CC + "/settings.local.json",
  TAMPER_HOME + TAMPER_CX + "/hooks.json",
  TAMPER_HOME + TAMPER_CX + "/config.toml",
  TAMPER_HOME + TAMPER_AGY + "/hooks.json",
  TAMPER_HOME + TAMPER_SG + "/hooks",
  TAMPER_HOME + TAMPER_SG + "/policy.json",
  TAMPER_HOME + TAMPER_SG + "/.policy-cache.json",
  // The cloud credential (contains the API key) — never readable via a tool.
  TAMPER_HOME + TAMPER_SG + "/cloud-guard.json"
];
var TAMPER_INSTALL = "/solongate";
var TAMPER_PROTECTED_GLOBS = [
  "**" + TAMPER_CC + "/settings.json",
  "**" + TAMPER_CC + "/settings.local.json",
  "**" + TAMPER_CX + "/hooks.json",
  "**" + TAMPER_CX + "/config.toml",
  "**" + TAMPER_AGY + "/hooks.json",
  "**" + TAMPER_SG + "/hooks/**",
  "**" + TAMPER_SG + "/policy.json",
  "**" + TAMPER_SG + "/.policy-cache.json",
  "**" + TAMPER_SG + "/.policy-cache-*.json",
  "**" + TAMPER_SG + "/.pi-config-cache.json",
  "**" + TAMPER_SG + "/cloud-guard.json",
  "**" + TAMPER_SG + "/.opa-wasm-*.json",
  "**" + TAMPER_SG + "/.ratelimit-*.json",
  // Persistent host data (DB + audit JSONL) at ~/.solongate/data
  "**" + TAMPER_SG + "/data/**",
  // Customer install layout (zip extracted as solongate/)
  "**" + TAMPER_INSTALL + "/compose/**",
  "**" + TAMPER_INSTALL + "/data/**",
  "**" + TAMPER_INSTALL + "/images/**",
  "**" + TAMPER_INSTALL + "/helm/**",
  "**" + TAMPER_INSTALL + "/solongate.exe",
  "**" + TAMPER_INSTALL + "/setup.sh"
];
var TAMPER_BASENAMES = [
  "guard.mjs",
  "audit.mjs",
  "stop.mjs",
  "shield.mjs",
  "policy.json",
  // Prefixes (substring match) so per-agent runtime state can't be deleted or
  // rewritten via a shell command either — `.policy-cache-<agent>.json`,
  // `.ratelimit-<agent>.json`, `.opa-wasm-<agent>.json`. Editing these could
  // otherwise flip enforcement off until the next cloud refresh; deleting just
  // forces a refetch, but neither should be reachable from an agent tool call.
  ".policy-cache",
  ".ratelimit-",
  ".opa-wasm-",
  ".pi-config-cache",
  "cloud-guard.json",
  // Customer install: DB and wizard exe
  "solongate.db",
  "solongate.exe"
];
var TAMPER_PATH_FIELDS = /* @__PURE__ */ new Set([
  "file_path",
  "path",
  "target_file",
  "notebook_path",
  "dest",
  "destination",
  "source",
  "src",
  "from",
  "to",
  "directory",
  "dir",
  "folder",
  // Antigravity CLI file-tool arg names (camelCase, lowercased here): its
  // write/read/list tools carry the path in these, so tamper protection sees it.
  "targetfile",
  "absolutepath",
  "filepath"
]);
function normTamperPath(p) {
  return String(p || "").replace(/\\/g, "/").toLowerCase();
}
function isProtectedPath(p) {
  if (!p)
    return false;
  const np = normTamperPath(p);
  for (const abs of TAMPER_PROTECTED_ABS) {
    if (np === abs || np.startsWith(abs + "/"))
      return abs;
  }
  for (const g of TAMPER_PROTECTED_GLOBS) {
    if (matchPathGlob(np, g))
      return g;
  }
  if (/\/\.claude\/settings(\.local)?\.json$/.test(np))
    return "settings.json";
  if (/\/\.solongate\/hooks(\/|$)/.test(np))
    return "solongate-hooks";
  if (/\/\.codex\/(hooks\.json|config\.toml)$/.test(np))
    return "codex-hooks";
  if (/\/\.gemini\/config\/hooks\.json$/.test(np))
    return "antigravity-hooks";
  if (/(^|\/)\.solongate\//.test(np)) {
    const base = np.slice(np.lastIndexOf("/") + 1);
    for (const b of TAMPER_BASENAMES) {
      if (base.startsWith(b.toLowerCase()))
        return b;
    }
  }
  return false;
}
function commandTargetsProtected(cmd) {
  const c = String(cmd || "").toLowerCase();
  if (!c)
    return false;
  for (const b of TAMPER_BASENAMES) {
    if (c.includes(b.toLowerCase()))
      return b;
  }
  if (/\.claude[\\/]+settings(\.local)?\.json/.test(c))
    return "settings.json";
  if (/\.solongate[\\/]+hooks/.test(c))
    return "solongate-hooks";
  if (/\.codex[\\/]+(hooks\.json|config\.toml)/.test(c))
    return "codex-hooks";
  if (/\.gemini[\\/]+config[\\/]+hooks\.json/.test(c))
    return "antigravity-hooks";
  if (/[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]/.test(c))
    return "solongate-install";
  const mutating = /\b(post|put|delete|patch)\b/.test(c) || /(-x|--request|-method)\s+(post|put|delete|patch)\b/.test(c);
  if (mutating && /api\/v1\/(policies|audit-logs)/.test(c))
    return "api-policies-mutation";
  return false;
}
function extractTargetPaths(args) {
  const out = [];
  if (typeof args !== "object" || !args)
    return out;
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (TAMPER_PATH_FIELDS.has(lk) && typeof v === "string")
      out.push(v);
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item && typeof item === "object") {
          for (const [k2, v2] of Object.entries(item)) {
            if (TAMPER_PATH_FIELDS.has(k2.toLowerCase()) && typeof v2 === "string")
              out.push(v2);
          }
        }
      }
    }
  }
  return out;
}
function tamperCheck(toolName, args) {
  const tn = String(toolName || "").toLowerCase();
  const isExec = TAMPER_GUARD_TOOLS_EXEC.has(tn) || /bash|shell|exec|powershell|cmd|run|eval/.test(tn);
  for (const p of extractTargetPaths(args)) {
    const hit = isProtectedPath(p);
    if (hit)
      return 'Tamper protection: access to "' + p + '" is blocked (protected: ' + hit + ")";
  }
  if (isExec) {
    for (const cmd of extractCommands(args)) {
      const hit = commandTargetsProtected(cmd);
      if (hit)
        return 'Tamper protection: command references protected resource "' + hit + '" \u2014 blocked';
    }
  }
  return null;
}
var DLP_PATTERNS = [
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "Private key block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "Anthropic key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "OpenAI key", re: /sk-(proj-)?[A-Za-z0-9_-]{20,}/ },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{20,}/ },
  { name: "GitHub fine-grained PAT", re: /github_pat_[A-Za-z0-9_]{20,}/ },
  { name: "GitLab token", re: /glpat-[A-Za-z0-9_-]{20,}/ },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "Stripe key", re: /[sr]k_(live|test)_[A-Za-z0-9]{20,}/ },
  { name: "SendGrid key", re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/ },
  { name: "Twilio key", re: /SK[0-9a-fA-F]{32}/ },
  { name: "npm token", re: /npm_[A-Za-z0-9]{36}/ },
  { name: "JWT", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "Bearer token", re: /bearer\s+[A-Za-z0-9._-]{20,}/i },
  // Kept in step with packages/guard-go/dlp.go, name for name and
  // expression for expression. The two lists had drifted to 14 here
  // against 74 there, and a name this list does not carry silently stops
  // being enforced on every machine that runs the hook rather than the
  // binary — which is every machine by default. dlp-parity.mjs holds them
  // together now.
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_+-]{40,}/ },
  { name: "Twilio account SID", re: /AC[0-9a-fA-F]{32}/ },
  { name: "Mailgun key", re: /key-[0-9a-f]{32}/ },
  { name: "Mailchimp key", re: /[0-9a-f]{32}-us[0-9]{1,2}/ },
  { name: "DigitalOcean token", re: /dop_v1_[0-9a-f]{64}/ },
  { name: "Databricks token", re: /dapi[0-9a-f]{32}/ },
  { name: "Shopify token", re: /shp(at|ca|pa|ss)_[0-9a-fA-F]{32}/ },
  { name: "Square token", re: /sq0(atp|csp)-[0-9A-Za-z_-]{22,43}/ },
  { name: "Telegram bot token", re: /[0-9]{8,10}:AA[0-9A-Za-z_-]{33}/ },
  { name: "Postman key", re: /PMAK-[0-9a-f]{24}-[0-9a-f]{34}/ },
  { name: "Doppler token", re: /dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}/ },
  { name: "HashiCorp Vault token", re: /hvs\.[A-Za-z0-9_-]{24,}/ },
  { name: "New Relic key", re: /NRAK-[A-Z0-9]{27}/ },
  { name: "Grafana token", re: /glc_[A-Za-z0-9+\/=_-]{32,}/ },
  { name: "Razorpay key", re: /rzp_(live|test)_[0-9A-Za-z]{14}/ },
  { name: "Linear key", re: /lin_api_[0-9A-Za-z]{40,}/ },
  { name: "Figma token", re: /figd_[0-9A-Za-z_-]{40,}/ },
  { name: "Atlassian token", re: /ATATT3[0-9A-Za-z_=.-]{20,}/ },
  { name: "Google OAuth token", re: /ya29\.[0-9A-Za-z_-]{50,}/ },
  { name: "Google OAuth refresh", re: /1\/\/0[0-9A-Za-z_-]{30,}/ },
  { name: "Alibaba access key", re: /LTAI[0-9A-Za-z]{20}/ },
  { name: "Tencent secret id", re: /AKID[0-9A-Za-z]{13,40}/ },
  { name: "Hugging Face token", re: /hf_[0-9A-Za-z]{34,}/ },
  { name: "Replicate token", re: /r8_[0-9A-Za-z]{37,}/ },
  { name: "Groq key", re: /gsk_[0-9A-Za-z]{48,}/ },
  { name: "OpenRouter key", re: /sk-or-v1-[0-9a-f]{64}/ },
  { name: "Perplexity key", re: /pplx-[0-9A-Za-z]{40,}/ },
  { name: "xAI key", re: /xai-[0-9A-Za-z]{40,}/ },
  { name: "LangSmith key", re: /lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/ },
  { name: "Stripe webhook secret", re: /whsec_[0-9A-Za-z]{32,}/ },
  { name: "Plaid token", re: /access-(sandbox|development|production)-[0-9a-f-]{36}/ },
  { name: "Braintree token", re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/ },
  { name: "Discord bot token", re: /[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}/ },
  { name: "Discord webhook", re: /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[0-9A-Za-z_-]{60,}/ },
  { name: "Slack app token", re: /xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+/ },
  { name: "Sentry DSN", re: /https:\/\/[0-9a-f]{32}@[0-9a-z.-]+sentry\.io\/[0-9]+/ },
  { name: "Supabase token", re: /sbp_[0-9a-f]{40}/ },
  { name: "PlanetScale token", re: /pscale_tkn_[0-9A-Za-z._-]{32,}/ },
  { name: "PlanetScale password", re: /pscale_pw_[0-9A-Za-z._-]{32,}/ },
  { name: "Airtable token", re: /pat[0-9A-Za-z]{14}\.[0-9a-f]{64}/ },
  { name: "Cloudinary URL", re: /cloudinary:\/\/[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+/ },
  { name: "MongoDB SRV URI", re: /mongodb\+srv:\/\/[^\s:@]+:[^\s:@]+@[0-9a-z.-]+/ },
  { name: "Terraform Cloud token", re: /[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}/ },
  { name: "PyPI token", re: /pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}/ },
  { name: "RubyGems key", re: /rubygems_[0-9a-f]{48}/ },
  { name: "NuGet key", re: /oy2[a-z0-9]{43}/ },
  { name: "Docker Hub token", re: /dckr_pat_[0-9A-Za-z_-]{27,}/ },
  { name: "Notion token", re: /ntn_[0-9A-Za-z]{40,}/ },
  { name: "Dropbox token", re: /sl\.[0-9A-Za-z_-]{130,}/ },
  { name: "Sentry auth token", re: /sntrys_[0-9A-Za-z_=+\/-]{40,}/ },
  { name: "Contentful token", re: /CFPAT-[0-9A-Za-z_-]{40,}/ },
  { name: "Typeform token", re: /tfp_[0-9A-Za-z_-]{40,}/ },
  { name: "Pinecone key", re: /pcsk_[0-9A-Za-z_-]{40,}/ },
  { name: "WooCommerce key", re: /c[ks]_[0-9a-f]{40}/ },
  { name: "PostHog key", re: /ph[cs]_[0-9A-Za-z]{40,}/ }
];
var dlpGlobCollapse = /\*{2,}/g;
var DLP_MAX_FILE_BYTES = 1048576;
function dlpGlobToRe(glob) {
  let re = "";
  for (const ch of String(glob || "").replace(dlpGlobCollapse, "*")) {
    if (ch === "*")
      re += "[^\\s]*";
    else if (".+?^${}()|[]\\".indexOf(ch) !== -1)
      re += "\\" + ch;
    else
      re += ch;
  }
  return new RegExp(re, "i");
}
function dlpViews(text) {
  const views = [text];
  try {
    const dequoted = text.replace(/[`'"\\]/g, "");
    if (dequoted !== text)
      views.push(dequoted);
    const src = dequoted !== text ? text + "\n" + dequoted : text;
    const toks = src.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
    let decoded = "";
    for (const t of toks.slice(0, 60)) {
      try {
        const d = Buffer.from(t, "base64").toString("latin1");
        if (/[ -~]{8,}/.test(d))
          decoded += d + "\n";
      } catch {
      }
    }
    if (decoded)
      views.push(decoded);
  } catch {
  }
  return views;
}
function dlpScan(args, cfg) {
  if (!cfg)
    return null;
  let text = "";
  try {
    text = JSON.stringify(args || {});
  } catch {
    return null;
  }
  text = text.replace(/\[REDACTED:[^\]]*\]/g, "");
  const views = dlpViews(text);
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (allow.has(p.name) && views.some((v) => p.re.test(v)))
      return p.name;
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try {
      const re = dlpGlobToRe(c.re);
      if (views.some((v) => re.test(v)))
        return c.name || "custom pattern";
    } catch {
    }
  }
  return null;
}
function egressSecretCheck(args, sec, cwd) {
  try {
    const dlp = sec && sec.dlpBlock;
    if (!dlp)
      return null;
    const base = cwd || process.cwd();
    for (const cmd of extractCommands(args)) {
      const c = String(cmd || "");
      const lc = c.toLowerCase();
      if (!/\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b/.test(lc))
        continue;
      if (!/https?:\/\//.test(lc) && !/@[\w.-]+:/.test(c) && !/\b\S+:\S/.test(c))
        continue;
      const files = /* @__PURE__ */ new Set();
      let m;
      for (const re of [
        /@([^\s'"|>&]+)/g,
        /(?:-T|--upload-file|--data-binary|--data-raw|--data|-d|-F|--form)[=\s]+@?([^\s'"|>&]+)/g,
        /\bcat\s+([^\s'"|>&]+)/g,
        /<\s*([^\s'"|>&]+)/g
      ]) {
        while (m = re.exec(c)) {
          const f = m[1];
          if (f && f !== "-" && !/^https?:\/\//.test(f) && !/^[@{[]/.test(f))
            files.add(f);
        }
      }
      for (let f of files) {
        if (f.startsWith("~"))
          f = homedir() + f.slice(1);
        let abs;
        try {
          abs = isAbsolute(f) ? f : resolve(base, f);
        } catch {
          continue;
        }
        let content = null;
        try {
          const st = statSync(abs);
          if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES)
            continue;
        } catch {
          continue;
        }
        try {
          content = readFileSync(abs, "utf-8");
        } catch {
          continue;
        }
        if (!content)
          continue;
        const hit = dlpScan(content, dlp);
        if (hit)
          return 'DLP: outbound transfer of "' + f + '" is blocked - it contains a ' + hit + " (egress protection)";
      }
    }
  } catch {
  }
  return null;
}
function dlpRedactText(text, cfg) {
  if (!cfg || typeof text !== "string")
    return text;
  let out = text;
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (!allow.has(p.name))
      continue;
    const g = p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g";
    try {
      out = out.replace(new RegExp(p.re.source, g), `[REDACTED:${p.name}]`);
    } catch {
    }
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try {
      const re = dlpGlobToRe(c.re);
      out = out.replace(new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"), `[REDACTED:${c.name || "custom"}]`);
    } catch {
    }
  }
  return out;
}
function dlpRedactReadPlan(toolName, args, dlp, cwd) {
  try {
    if (!dlp || !args)
      return null;
    const base = cwd || process.cwd();
    const abends = (f) => {
      let x = f;
      if (x.startsWith("~"))
        x = homedir() + x.slice(1);
      return isAbsolute(x) ? x : resolve(base, x);
    };
    const redactCopy = (abs) => {
      let content;
      try {
        const st = statSync(abs);
        if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES)
          return "SKIP";
        content = readFileSync(abs, "utf-8");
      } catch {
        return "SKIP";
      }
      if (dlpScan(content, dlp) == null)
        return "CLEAN";
      try {
        const dir = join(resolve(homedir(), ".solongate"), ".redacted");
        mkdirSync(dir, { recursive: true });
        const tmp = join(dir, createHash("sha256").update(abs).digest("hex").slice(0, 24) + "-" + (abs.split("/").pop() || "f"));
        writeFileSync(tmp, dlpRedactText(content, dlp));
        return tmp;
      } catch {
        return "FAILED";
      }
    };
    for (const [k, v] of Object.entries(args)) {
      if (k === "command" || typeof v !== "string" || !v || !/[./]/.test(v))
        continue;
      const r = redactCopy(abends(v));
      if (r === "SKIP" || r === "CLEAN")
        continue;
      if (r === "FAILED")
        return { block: true };
      return { rewrite: { [k]: r } };
    }
    const GLOB_META = /[*?\[]/;
    const expandGlob = (absGlob) => {
      try {
        const dir = dirname(absGlob);
        const base2 = absGlob.slice(dir.length + 1);
        if (!GLOB_META.test(base2))
          return [absGlob];
        const re = new RegExp("^" + base2.replace(/\*{2,}/g, "*").replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$");
        return readdirSync(dir).filter((f) => re.test(f)).map((f) => join(dir, f));
      } catch {
        return [];
      }
    };
    const cmd = typeof args.command === "string" ? args.command : "";
    if (cmd && /\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b/.test(cmd.toLowerCase())) {
      let newCmd = cmd, changed = false;
      for (const tok of cmd.split(/[\s'"|<>;&()]+/)) {
        if (!tok || tok.startsWith("-") || !/[./]/.test(tok))
          continue;
        if (GLOB_META.test(tok)) {
          for (const f of expandGlob(abends(tok))) {
            const rg = redactCopy(f);
            if (rg !== "SKIP" && rg !== "CLEAN")
              return { block: true };
          }
          continue;
        }
        const r = redactCopy(abends(tok));
        if (r === "SKIP" || r === "CLEAN")
          continue;
        if (r === "FAILED")
          return { block: true };
        newCmd = newCmd.split(tok).join(r);
        changed = true;
      }
      if (changed)
        return { rewrite: { command: newCmd } };
    }
  } catch {
    return { block: true };
  }
  return null;
}
var RL_WINDOWS = [
  { key: "perDay", ms: 864e5, label: "day" },
  { key: "perHour", ms: 36e5, label: "hour" },
  { key: "perMinute", ms: 6e4, label: "minute" }
];
var RL_REC = 14;
var RL_MAX_READ = 1048576;
var RL_MAX_FILE = 4194304;
function rateLimitCheck(agentKey, limits) {
  try {
    const dir = resolve(homedir(), ".solongate");
    const file = join(dir, ".ratelimit-" + agentKey + ".log");
    const now = Date.now();
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
    }
    try {
      appendFileSync(file, String(now).padStart(13, "0") + "\n");
    } catch {
      return null;
    }
    let size = 0;
    try {
      size = statSync(file).size;
    } catch {
      return null;
    }
    const start = Math.max(0, size - RL_MAX_READ);
    const from = start - start % RL_REC;
    let buf = "";
    try {
      const fd = openSync(file, "r");
      const b = Buffer.alloc(size - from);
      readSync(fd, b, 0, b.length, from);
      closeSync(fd);
      buf = b.toString("latin1");
    } catch {
      return null;
    }
    const stamps = [];
    for (let i = 0; i + RL_REC <= buf.length; i += RL_REC) {
      const t = parseInt(buf.slice(i, i + 13), 10);
      if (Number.isFinite(t) && now - t < 864e5)
        stamps.push(t);
    }
    for (const w of RL_WINDOWS) {
      const limit = limits[w.key];
      if (limit > 0) {
        const count = stamps.reduce((n, t) => now - t < w.ms ? n + 1 : n, 0);
        if (count > limit)
          return { window: w.label, limit };
      }
    }
    if (size > RL_MAX_FILE) {
      try {
        const tmp = file + "." + process.pid + ".tmp";
        writeFileSync(tmp, stamps.map((t) => String(t).padStart(13, "0") + "\n").join(""));
        renameSync(tmp, file);
      } catch {
      }
    }
    return null;
  } catch {
    return null;
  }
}
function securityLayerCheck(toolName, args, cfg, agentKey) {
  if (!cfg)
    return null;
  try {
    if (cfg.dlpBlock) {
      const hit = dlpScan(args, cfg.dlpBlock);
      if (hit)
        return "Security layer (DLP): blocked - arguments contain a " + hit + ". Blocked by SolonGate - check your dashboard for details.";
    }
    if (cfg.rateLimit) {
      const hit = rateLimitCheck(agentKey, cfg.rateLimit);
      if (hit) {
        return "Security layer (rate limit): exceeded " + hit.limit + " calls/" + hit.window + " for this agent. Blocked by SolonGate - check your dashboard to review or adjust the limit.";
      }
    }
  } catch {
  }
  return null;
}
function permissionApplies(rule, toolName) {
  if (!rule.permission)
    return true;
  const perms = Array.isArray(rule.permission) ? rule.permission : [rule.permission];
  if (perms.length === 0)
    return true;
  const guessed = guessPermission(toolName);
  return perms.includes(guessed);
}
function patternsOf(constraint) {
  if (!constraint)
    return null;
  const list = constraint.denied || constraint.allowed;
  return Array.isArray(list) && list.length > 0 ? list : null;
}
function ruleMatches(rule, args, isExec) {
  const fnPats = patternsOf(rule.filenameConstraints);
  if (fnPats) {
    const filenames = extractFilenames(args);
    for (const fn of filenames) {
      for (const pat of fnPats) {
        if (matchGlob(fn, pat))
          return { kind: "filename", value: fn, pattern: pat };
      }
    }
  }
  const urlPats = patternsOf(rule.urlConstraints);
  if (urlPats) {
    const urls = extractUrls(args);
    for (const url of urls) {
      for (const pat of urlPats) {
        if (matchGlob(url, pat))
          return { kind: "URL", value: url, pattern: pat };
      }
    }
  }
  const cmdPats = patternsOf(rule.commandConstraints);
  if (cmdPats) {
    const cmds = extractCommands(args);
    for (const cmd of cmds) {
      for (const pat of cmdPats) {
        if (matchGlob(cmd, pat))
          return { kind: "command", value: cmd.slice(0, 60), pattern: pat };
      }
    }
  }
  const pathPats = patternsOf(rule.pathConstraints);
  if (pathPats) {
    const paths = extractPaths(args, isExec);
    for (const p of paths) {
      for (const pat of pathPats) {
        if (matchPathGlob(p, pat))
          return { kind: "path", value: p, pattern: pat };
      }
    }
  }
  return null;
}
function evaluate(policy, args, toolName) {
  if (!policy || !policy.rules)
    return null;
  const enabledRules = policy.rules.filter((r) => r.enabled !== false);
  const mode = policy.mode === "whitelist" ? "whitelist" : "denylist";
  const isExec = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || "").toLowerCase());
  const denyRules = enabledRules.filter((r) => r.effect === "DENY" && permissionApplies(r, toolName)).sort((a, b) => (a.priority || 100) - (b.priority || 100));
  for (const rule of denyRules) {
    const m = ruleMatches(rule, args, isExec);
    if (m)
      return "Blocked by policy: " + m.kind + ' "' + m.value + '" matches "' + m.pattern + '"';
  }
  if (mode === "whitelist") {
    const allowRules = enabledRules.filter((r) => r.effect === "ALLOW" && permissionApplies(r, toolName));
    if (allowRules.length === 0) {
      return "Blocked by policy: strict whitelist mode is on and no ALLOW rule applies to " + (toolName || "this tool");
    }
    let matched = false;
    for (const rule of allowRules) {
      if (ruleMatches(rule, args, isExec)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return "Blocked by policy: strict whitelist mode \u2014 request does not match any ALLOW rule";
    }
  }
  return null;
}
function djb2(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++)
    h = (h << 5) + h + str.charCodeAt(i) | 0;
  return (h >>> 0).toString(36);
}
function extractWasmFromBundle(buf) {
  if (buf[0] === 31 && buf[1] === 139) {
    const tar = gunzipSync(buf);
    let offset = 0;
    while (offset < tar.length - 512) {
      const nameEnd = tar.indexOf(0, offset);
      const name = tar.subarray(offset, Math.min(nameEnd, offset + 100)).toString("utf-8");
      if (!name || name.length === 0)
        break;
      const sizeStr = tar.subarray(offset + 124, offset + 136).toString("utf-8").trim();
      const size = parseInt(sizeStr, 8) || 0;
      offset += 512;
      if (name === "policy.wasm" || name === "./policy.wasm" || name.endsWith("/policy.wasm")) {
        return Buffer.from(tar.subarray(offset, offset + size));
      }
      offset += Math.ceil(size / 512) * 512;
    }
    throw new Error("policy.wasm not found in OPA bundle");
  }
  if (buf[0] === 0 && buf[1] === 97 && buf[2] === 115 && buf[3] === 109) {
    return buf;
  }
  throw new Error("Unknown OPA bundle format");
}
var OPA_WASM_TTL_MS = 24 * 60 * 60 * 1e3;
async function getOpaWasmBytes(policy) {
  if (!policy || !policy.id)
    return null;
  const fp = djb2(JSON.stringify(policy.rules || []) + "|" + (policy.mode || ""));
  const agentKey = (AGENT_ID || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
  const cacheFile = join(resolve(homedir(), ".solongate"), ".opa-wasm-" + agentKey + ".json");
  let stale = null;
  try {
    if (existsSync(cacheFile)) {
      const c = JSON.parse(readFileSync(cacheFile, "utf-8"));
      if (c && c.wasm && c.fp === fp) {
        stale = new Uint8Array(Buffer.from(c.wasm, "base64"));
        if (c._ts && Date.now() - c._ts < OPA_WASM_TTL_MS) {
          return stale;
        }
      }
    }
  } catch {
  }
  try {
    const res = await fetch(
      API_URL + "/api/v1/policies/" + encodeURIComponent(policy.id) + "/wasm",
      { headers: AUTH_HEADERS, signal: AbortSignal.timeout(2500) }
    );
    if (!res.ok)
      return stale;
    const bundle = Buffer.from(await res.arrayBuffer());
    const wasm = extractWasmFromBundle(bundle);
    try {
      mkdirSync(resolve(homedir(), ".solongate"), { recursive: true, mode: SG_DIR_MODE });
      writeFileSync(cacheFile, JSON.stringify({ _ts: Date.now(), fp, wasm: Buffer.from(wasm).toString("base64") }));
    } catch {
    }
    return new Uint8Array(wasm);
  } catch {
    return stale;
  }
}
var _loadPolicyFn = null;
var _loadPolicyTried = false;
async function getLoadPolicy() {
  if (_loadPolicyTried)
    return _loadPolicyFn;
  _loadPolicyTried = true;
  try {
    const mod = await Promise.resolve().then(() => (init_src(), src_exports));
    _loadPolicyFn = mod.loadPolicy || mod.default && mod.default.loadPolicy || null;
  } catch {
    _loadPolicyFn = null;
  }
  return _loadPolicyFn;
}
async function evaluateWithOpa(policy, args, toolName, cwd) {
  if (!policy || !policy.rules)
    return void 0;
  try {
    const loadPolicy2 = await getLoadPolicy();
    if (!loadPolicy2)
      return void 0;
    const wasmBytes = await getOpaWasmBytes(policy);
    if (!wasmBytes)
      return void 0;
    const opaPolicy = await loadPolicy2(wasmBytes, { initial: 5 });
    const isExecTool = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || "").toLowerCase());
    const refFiles = isExecTool && typeof readReferencedFiles === "function" ? readReferencedFiles(args, cwd || process.cwd()) : {};
    const expandedArgs = { ...args && typeof args === "object" ? args : {} };
    for (const [, content] of Object.entries(refFiles)) {
      const lines = String(content).split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
      if (lines.length > 0) {
        const extra = lines.join("; ");
        if (typeof expandedArgs.command === "string") {
          expandedArgs.command = expandedArgs.command + "; " + extra;
        } else {
          expandedArgs.command = extra;
        }
      }
    }
    const ACCESS_FIELDS = /* @__PURE__ */ new Set(["file_path", "path", "target_file", "notebook_path", "filename", "dest", "destination", "source", "src", "from", "to", "directory", "dir", "folder", "url", "urls", "uri", "href", "link", "endpoint", "absolutepath", "targetfile", "filepath"]);
    let accessArgs = expandedArgs;
    if (!isExecTool && expandedArgs && typeof expandedArgs === "object") {
      accessArgs = {};
      for (const [k, v] of Object.entries(expandedArgs)) {
        if (ACCESS_FIELDS.has(k.toLowerCase()))
          accessArgs[k] = v;
      }
    }
    const input2 = {
      tool_name: toolName || "",
      permission: guessPermission(toolName),
      trust_level: "TRUSTED",
      arguments: expandedArgs,
      paths: extractPaths(accessArgs, isExecTool),
      commands: extractCommands(expandedArgs),
      urls: extractUrls(accessArgs),
      filenames: extractFilenames(accessArgs)
    };
    if (isExecTool) {
      for (const gp of expandCommandGlobs(expandedArgs, cwd)) {
        input2.paths.push(gp);
        const bn = gp.split("/").pop();
        if (bn)
          input2.filenames.push(bn);
      }
    }
    for (const sp of expandSearchRoots(toolName, expandedArgs, cwd)) {
      input2.paths.push(sp);
      const bn = sp.split("/").pop();
      if (bn)
        input2.filenames.push(bn);
    }
    if (process.env.SOLONGATE_DEBUG) {
    }
    const results = opaPolicy.evaluate(input2);
    const decision = results && results[0] && results[0].result;
    if (!decision || !decision.effect)
      return null;
    const mode = policy.mode === "whitelist" ? "whitelist" : "denylist";
    const matched = decision.matched_rule != null;
    const eff = decision.effect;
    if (mode === "denylist") {
      if (eff === "DENY" && matched)
        return "[SolonGate OPA] " + (decision.reason || "Blocked by policy");
      if (eff === "REVIEW" && matched)
        return { white: false, reason: decision.reason, ruleId: decision.matched_rule };
      return { white: true, ruleId: matched ? decision.matched_rule : null };
    }
    if (eff === "DENY" && matched)
      return "[SolonGate OPA] " + (decision.reason || "Blocked by policy");
    if (eff === "REVIEW" && matched)
      return { white: false, reason: decision.reason, ruleId: decision.matched_rule };
    if (eff === "ALLOW" && matched)
      return { white: true, ruleId: decision.matched_rule };
    return "[SolonGate OPA] " + (decision.reason || "Blocked by policy: no ALLOW rule matched");
  } catch {
    return void 0;
  }
}
function applyPatchTargets(patch) {
  const out = [];
  if (typeof patch !== "string" || !patch.includes("*** "))
    return out;
  const re = /^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$/gm;
  let m;
  while (m = re.exec(patch))
    if (m[1])
      out.push(m[1]);
  const mv = /^\*\*\*\s+Move\s+to:\s*(.+?)\s*$/gm;
  while (m = mv.exec(patch))
    if (m[1])
      out.push(m[1]);
  return out;
}
function liftFreeformPatchPaths(call) {
  const cmd = call.command;
  if (call.tool !== "apply_patch" && !(typeof cmd === "string" && cmd.startsWith("*** Begin Patch")))
    return;
  const targets = applyPatchTargets(cmd);
  if (!targets.length)
    return;
  call.args = { ...call.args };
  if (!call.args.file_path)
    call.args.file_path = targets[0];
  if (!Array.isArray(call.args.edits))
    call.args.edits = targets.map((f) => ({ file_path: f }));
}
function normalizeToolCall(raw) {
  const parsed = CLIENT.parse(raw) || {};
  const tool = parsed.tool || "";
  const call = {
    client: AGENT_TYPE,
    // The client's own tool name, kept verbatim for logs and audit. Layers must
    // NOT branch on it: clients name the same capability differently (Bash /
    // run_command / shell). `permission` below is the neutral classification.
    tool,
    permission: guessPermission(tool),
    args: parsed.args || {},
    command: parsed.command ?? null,
    cwd: parsed.cwd || process.cwd(),
    sessionId: parsed.sessionId || "",
    response: parsed.response || {},
    raw
  };
  liftFreeformPatchPaths(call);
  return call;
}
var input = "";
function readReferencedFiles(args, cwd) {
  const out = {};
  const MAX_FILES = 3, MAX_BYTES = 65536;
  const cands = /* @__PURE__ */ new Set();
  const INTERP = /^(?:bash|sh|zsh|ksh|dash|ash|python3?|node|deno|bun|ruby|perl|php|pwsh|powershell|source|\.)$/i;
  if (args && typeof args === "object") {
    for (const f of ["command", "cmd", "script", "shell", "code"]) {
      const v = args[f];
      if (typeof v !== "string")
        continue;
      const toks = v.split(/[\s'"();|&<>]+/).filter(Boolean);
      for (let i = 0; i < toks.length - 1; i++) {
        if (!INTERP.test(toks[i]))
          continue;
        let j = i + 1;
        while (j < toks.length && toks[j].startsWith("-"))
          j++;
        if (j < toks.length)
          cands.add(toks[j]);
      }
    }
  }
  let n = 0;
  for (const c of cands) {
    if (n >= MAX_FILES)
      break;
    try {
      const p = resolve(cwd || process.cwd(), c);
      if (!existsSync(p))
        continue;
      const st = statSync(p);
      if (!st.isFile() || st.size > MAX_BYTES)
        continue;
      out[c] = readFileSync(p, "utf-8").slice(0, MAX_BYTES);
      n++;
    } catch {
    }
  }
  return out;
}
if (!REFRESH_MODE) {
  input += SG_STDIN;
}
(async () => {
  try {
    setTimeout(() => {
      try {
        process.exit(process.exitCode || 0);
      } catch {
      }
    }, 8e3).unref();
  } catch {
  }
  try {
    if (REFRESH_MODE)
      return;
    if (process.env.SOLONGATE_DEBUG) {
    }
    const _evalStart = SG_ORIGIN_MS;
    try {
      const raw = JSON.parse(input);
      if (process.env.SOLONGATE_DEBUG) {
        try {
          const { appendFileSync: afs, mkdirSync: mds } = await import("node:fs");
          mds(resolve(".solongate"), { recursive: true });
          const debugLine = JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), hook: "guard", argv: process.argv.slice(2), tool_name: raw.tool_name || raw.toolName || raw.command, agent_id: AGENT_ID }) + "\n";
          afs(resolve(".solongate", ".debug-guard-log"), debugLine);
        } catch {
        }
      }
      CALL_ID = String(raw.tool_use_id || raw.toolUseId || raw.tool_call_id || "");
      try {
        CALL_FP = callFingerprint(JSON.stringify(raw.tool_input || raw.toolInput || raw.params || {}));
      } catch {
        CALL_FP = "";
      }
      const call = normalizeToolCall(raw);
      const args = call.args;
      const toolName = call.tool;
      if (process.env.SOLONGATE_DEBUG) {
        try {
          process.stderr.write("[SolonGate CALL] " + JSON.stringify({
            permission: call.permission,
            args: call.args,
            command: call.command,
            cwd: call.cwd,
            sessionId: call.sessionId
          }) + "\n");
        } catch {
        }
      }
      try {
        const _ak = (AGENT_ID || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
        const _cf = join(resolve(homedir(), ".solongate"), ".policy-cache-" + _ak + ".json");
        let _selfProt = true, _sec = null, _cacheOk = false;
        try {
          const _c = JSON.parse(readFileSync(_cf, "utf-8"));
          _cacheOk = true;
          if (_c && typeof _c.selfProtect === "boolean")
            _selfProt = _c.selfProtect;
          if (_c && _c.security !== void 0)
            _sec = _c.security;
        } catch {
        }
        const _tr = _cacheOk && _selfProt ? tamperCheck(toolName, args) : null;
        const _er = !_tr && _cacheOk ? egressSecretCheck(args, _sec, call.cwd) : null;
        const _deny = _tr || _er;
        if (_deny) {
          const _logEntry = {
            tool: toolName,
            arguments: args,
            decision: "DENY",
            reason: _deny,
            permission: guessPermission(toolName),
            source: `${AGENT_TYPE}-guard`,
            agent_id: AGENT_TYPE,
            agent_name: AGENT_NAME,
            session_id: call.sessionId,
            evaluation_time_ms: Date.now() - _evalStart
          };
          try {
            writeLocalLog(_sec, { ts: (/* @__PURE__ */ new Date()).toISOString(), ..._logEntry });
          } catch {
          }
          try {
            if (!localLogsOnly(_sec))
              postAuditDetached(_logEntry);
          } catch {
          }
          if (AGENT_TYPE !== "codex")
            process.stderr.write(`[SolonGate ROUTE] BLACK (block)
`);
          writeDenyFlag(toolName);
          blockTool(_deny);
        }
      } catch (_e) {
        if (_e === SG_DONE)
          throw _e;
      }
      const hookCwd = call.cwd || process.cwd();
      let policy;
      let selfProtectEnabled = true;
      let securityCfg = null;
      const agentKey = (AGENT_ID || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
      const policyCacheFile = join(resolve(homedir(), ".solongate"), ".policy-cache-" + agentKey + ".json");
      const POLICY_TTL_MS = 1e4;
      try {
        let dashboardPolicy = null;
        let staleCache = null;
        let refreshDue = true;
        try {
          if (existsSync(policyCacheFile)) {
            const cached = JSON.parse(readFileSync(policyCacheFile, "utf-8"));
            if (cached)
              staleCache = cached;
            if (cached && cached._ts && Date.now() - cached._ts < POLICY_TTL_MS) {
              refreshDue = false;
              if (cached.policy)
                dashboardPolicy = cached.policy;
              if (typeof cached.selfProtect === "boolean")
                selfProtectEnabled = cached.selfProtect;
              if (cached.security !== void 0) {
                securityCfg = cached.security;
                writeLocalMarker(securityCfg);
              }
              if (cached.hookVersions)
                CLOUD_HOOK_VERSIONS = cached.hookVersions;
            }
          }
        } catch {
        }
        if (refreshDue) {
          if (!dashboardPolicy && staleCache) {
            dashboardPolicy = staleCache.policy;
            if (typeof staleCache.selfProtect === "boolean")
              selfProtectEnabled = staleCache.selfProtect;
            if (staleCache.security !== void 0)
              securityCfg = staleCache.security;
            if (staleCache.hookVersions)
              CLOUD_HOOK_VERSIONS = staleCache.hookVersions;
          }
          if (API_KEY) {
            try {
              const lock = join(resolve(homedir(), ".solongate"), ".policy-refresh-" + agentKey + ".lock");
              const due = !existsSync(lock) || Date.now() - statSync(lock).mtimeMs > 3e3;
              if (due) {
                try {
                  writeFileSync(lock, String(Date.now()));
                } catch {
                }
                spawn(process.execPath, [process.argv[1], AGENT_TYPE, AGENT_NAME, "--sg-refresh-policy"], { detached: true, stdio: "ignore", env: process.env }).unref();
              }
            } catch {
            }
          }
        }
        if (process.env.SOLONGATE_DEBUG) {
        }
        if (dashboardPolicy) {
          policy = dashboardPolicy;
        } else {
          const local = loadLocalPolicyFile(hookCwd);
          if (local) {
            policy = local.policy;
            if (local.security !== void 0) {
              securityCfg = local.security;
              writeLocalMarker(securityCfg);
            }
            if (local.selfProtect !== void 0)
              selfProtectEnabled = local.selfProtect;
          }
        }
      } catch {
      }
      if (process.env.SOLONGATE_DEBUG) {
      }
      {
        const scope = policy && Array.isArray(policy.agents) && policy.agents.length > 0 ? policy.agents : ["*"];
        if (!scope.includes("*") && !scope.includes(AGENT_TYPE)) {
          allowTool();
          return;
        }
      }
      if (process.env.SOLONGATE_DEBUG) {
      }
      let reason = selfProtectEnabled ? tamperCheck(toolName, args) : null;
      if (!reason)
        reason = securityLayerCheck(toolName, args, securityCfg, agentKey);
      if (process.env.SOLONGATE_DEBUG) {
      }
      let opaRoute = "white";
      if (reason) {
        opaRoute = "black";
      } else if (policy && policy.rules) {
        const opaResult = await evaluateWithOpa(policy, args, toolName, hookCwd);
        if (opaResult === void 0) {
          const legacy = evaluate(policy, args, toolName);
          if (typeof legacy === "string") {
            reason = legacy;
            opaRoute = "black";
          } else {
            opaRoute = "white";
          }
        } else if (typeof opaResult === "string") {
          reason = opaResult;
          opaRoute = "black";
        } else {
          opaRoute = "white";
        }
      }
      if (!reason && !CLIENT.redactsOutput && securityCfg && (securityCfg.dlpBlock || securityCfg.dlpRedact)) {
        const dlpCfg = securityCfg.dlpBlock || securityCfg.dlpRedact;
        const plan = dlpRedactReadPlan(toolName, args, dlpCfg, hookCwd);
        if (plan && plan.block) {
          reason = "Security layer (DLP): reading a file that contains a secret is blocked. Blocked by SolonGate.";
          opaRoute = "black";
        } else if (plan && plan.rewrite) {
          rewriteTool(plan.rewrite);
        }
      }
      if (AGENT_TYPE !== "codex")
        process.stderr.write(`[SolonGate ROUTE] ${opaRoute.toUpperCase()} (${reason ? "block" : "allow"})
`);
      try {
        const _fd = projectFlagDir();
        mkdirSync(_fd, { recursive: true });
        sweepLegacyFlagDir();
        const _rec = { ms: Date.now() - _evalStart, ts: Date.now(), tool: toolName, session: call.sessionId };
        writeFileSync(join(_fd, ".last-eval"), JSON.stringify(_rec));
        try {
          const ring = join(_fd, ".eval-ring.jsonl");
          appendFileSync(ring, JSON.stringify(_rec) + "\n");
          try {
            if (statSync(ring).size > 16384)
              writeFileSync(ring, readFileSync(ring, "utf-8").split("\n").filter(Boolean).slice(-50).join("\n") + "\n");
          } catch {
          }
        } catch {
        }
      } catch {
      }
      if (reason) {
        if (true) {
          try {
            const logEntry = {
              tool: toolName,
              arguments: args,
              decision: "DENY",
              reason,
              permission: guessPermission(toolName),
              source: `${AGENT_TYPE}-guard`,
              agent_id: AGENT_TYPE,
              agent_name: AGENT_NAME,
              session_id: call.sessionId,
              evaluation_time_ms: Date.now() - _evalStart
            };
            writeLocalLog(securityCfg, { ts: (/* @__PURE__ */ new Date()).toISOString(), ...logEntry });
            if (!localLogsOnly(securityCfg))
              postAuditDetached(logEntry);
          } catch {
          }
        }
        writeDenyFlag(toolName);
        blockTool(reason);
      }
    } catch {
    }
    await maybeSelfUpdate();
    allowTool();
  } catch (e) {
    if (e !== SG_DONE) {
      process.exitCode = process.exitCode || 0;
    }
  }
})();
