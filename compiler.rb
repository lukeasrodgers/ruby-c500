require 'byebug'
PAGE_SIZE = 65536  # webassembly native page size

# Print the message with a traceback, along with a line number if supplied, and exit.
def die(message, line = nil)
  STDERR.puts("\n" + "-" * 30 + "\n")
  puts Kernel.caller
  STDERR.puts("\n" + "-" * 30 + "\n")
  location = line ? " on line #{line + 1}" : ""
  STDERR.puts("error #{location}: #{message}")
  `exit 1`
end

class Emitter
  def initialize
    @emit_disabled = false
    @indent_level = 0
  end

  def emit(code)
    if !@emit_disabled
      puts " " * @indent_level + code
    end
  end

  def block(start:, finish:, &block)
    emit(start)
    @indent_level += 2
    yield
    @indent_level -= 2
    emit(finish)
  end

  def no_emit
    @emit_disabled = true
    begin
      yield
    ensure
      @emit_disabled = false
    end
  end
end

$emitter = Emitter.new

# seems like just a way to group up constants and then emit then at the ... top?
# of the wasm code? kinda like globals?
# or maybe just hardcoded/constant strings? to reuse where possible?
class StringPool
  attr_reader :base
  def initialize
    @base = @current = PAGE_SIZE
    @strs = {}
  end

  # @param s [String] what makes this bytes? just a byte string? in python binary string?
  # @return [Integer]
  def add(s)
    s = s + [0].pack("c*")
    if !@strs.key?(s)
      @strs[s] = @current
      @current += s.size
      if @current - @base > PAGE_SIZE
        die("string pool is too large")
      end
    end
    @strs[s]
  end

  # Make a webassembly str expression representing all the pooled strs
  # by why tho
  def pooled
    @strs.keys.flat_map {|k| k.chars.map{|c| escape(c.ord) } }.join
  end

  private

  def escape(c)
    if (31 < c && c < 127) && !'\\"'.include?(c.chr)
      c.chr
    else
      # FIXME escaping could be wrong?
      "\\#{c.to_s(16).rjust(2, '0')}"
    end
  end
end

$str_pool = StringPool.new

# Token kinds
# Literal tokens (symbols and keywords): the `content` of these will be the same as their `kind`
LITERAL_TOKENS = "typedef if else while do for return ++ -- << >> && || == <= >= != < > ( ) { } [ ] ; = + - * / % & | ^ , ! ~".split
# Meta tokens for unknown content, the end of the file, and type / name identifiers
TOK_INVALID, TOK_EOF, TOK_TYPE, TOK_NAME = "Invalid", "Eof", "Type", "Name"
# Constants
TOK_INTCONST, TOK_CHARCONST, TOK_STRCONST = "IntConst", "CharConst", "StrConst"

Token = Data.define(:kind, :content, :line)

class Lexer
  attr_reader :loc, :line
  def initialize(src:, types:, loc: 0, line: 0)
    @src = src
    @types = types
    @loc = loc
    @line = line
  end

  def clone
    self.class.new(src: @src, types: @types.dup, loc: @loc, line: @line)
  end

  # Tries to skips past one comment or whitespace character.
  # Returns True if one was present, False otherwise.
  def _skip_comment_ws
    if @src[@loc..].start_with?("//")
      while @loc < @src.size && @src[@loc] != "\n"
        @loc += 1
      end
      true
    elsif @src[@loc..].start_with?("/*")
      start_line = @line
      @loc += 2
      while !@src[@loc..].start_with?("*/") do
        if @loc >= @src.size
          die("unterminated multi-line comment", start_line)
        elsif @src[@loc] == "\n"
          @line += 1
        end
        @loc += 1
      end
      @loc += 2
      true
    elsif " \t\n".include?(@src[@loc])
      if @src[@loc] == "\n"
        @line += 1
      end
      @loc += 1
      true
    else
      false
    end
  end

  # Peek at the next token without consuming it. Consumes whitespace.
  # @return [Token]
  def peek
    # skip past whitespace
    loop do
      if @loc < @src.size && _skip_comment_ws
        next
      else
        break
      end
    end

    if @loc >= @src.size
      return Token.new(TOK_EOF, "", @line)
    end

    # identifiers and identifier-like tokens
    # we check identifiers before literal tokens so that "return0" isn't lexed as
    # "return", "0", but this means that we need to explicitly check for
    # identifier-like tokens so "return" isn't lexed as a Name just because it's `[a-z]+`
    r = /\A[a-zA-Z_][a-zA-Z0-9_]*/
    m = @src[@loc..].match(r)
    if m
      tok = m[0]
      if LITERAL_TOKENS.include?(tok)
        # for literal tokens, the kind is their symbol / keyword
        return Token.new(tok, tok, @line)
      end

      # lexer hack
      type = @types.include?(tok) ? TOK_TYPE : TOK_NAME
      return Token.new(type, tok, @line)
    end

    # int constants
    m = @src[@loc..].match(/\A[0-9]+/)
    if m
      return Token.new(TOK_INTCONST, m[0], @line)
    end

    # char constants
    escape = /(\\([\\abfnrtv'"?]|[0-7]{1,3}|x[A-Fa-f0-9]{1,2}))/
    m = @src[@loc..].match(escape)
    if m
      return Token.new(TOK_CHARCONST, m[0], @line)
    end

    # string constants
    # TODO refactor with escape above
    # TODO may need to fix ^ here as well
    m = @src[@loc..].match(/\A"([^"\\]|(\\([\\abfnrtv'"?]|[0-7]{1,3}|x[A-Fa-f0-9]{1,2})))*?(?<!\\)"/)
    if m
      return Token.new(TOK_STRCONST, m[0], @line)
    end

    # other tokens not caught by the identifier-like-token check above
    LITERAL_TOKENS.each do |token_kind|
      if @src[@loc..].start_with?(token_kind)
        # for literal tokens, the kind is their symbol / keyword
        return Token.new(token_kind, token_kind, @line)
      end
    end

    # emit a TOK_INVALID token with an arbitrary amount of context
    return Token.new(TOK_INVALID, @src[@loc..(@loc+10)], @line)
  end

  # Consume the next token. If `kind` is specified, die if the token doesn't match.
  def next(kind = nil)
    token = peek

    if kind && token.kind != kind
      die("expected #{kind}, got #{token.content}", @line)
    end

    if token.kind != TOK_INVALID
      @loc += token.content.size
    end

    return token
  end

  # If a token of the given kind is present, consume and return it. Otherwise do nothing.
  # @param kind [String]
  # @return [void, 
  def try_next(kind)
    if peek.kind == kind
      # TODO maybe rename to avoid confusing ruby parser?
      send(:next, kind)
    end
  end
end

class CType
  attr_accessor :decl_line, :pointer_level, :wasmtype

  def initialize(typename:, pointer_level: 0, array_size: nil, decl_line: nil)
    @typename = typename
    @pointer_level = pointer_level
    @array_size = array_size
    @decl_line = decl_line

    if !["char", "int"].include?(typename)
      die("unknown type #{typename}", decl_line)
    end
    @signed = true
    @wasmtype = "i32"
  end

  # Size of this type, in bytes.
  def sizeof
    if @typename == "char" and !is_ptr?
      1 * (@array_size || 1)
    end

    4 * (@array_size || 1)
  end

  # Whether this type is a pointer or not. Returns false for arrays of non-pointers like int _[5].
  def is_ptr?
    @pointer_level > 0
  end

  # Makes a new type one level of pointer less than this type, e.g. int** -> int*.
  # Errors if the type isn't a pointer.
  def less_ptr
    raise "bug: not a pointer #{self}" unless is_ptr?

    return self.class.new(typename: @typename, pointer_level: @pointer_level - 1, array_size: @array_size)
  end

  # Makes a new type one level of pointer higher than this type, e.g. int -> int*
  def more_ptr
    return self.class.new(typename: @typename, pointer_level: @pointer_level + 1, array_size: @array_size)
  end

  # Whether this type is an array.
  def is_arr?
    @array_size != nil
  end

  # Makes a new type that's the same as this type, except it isn't an array
  def as_non_array
    raise "bug: not an array #{self}" unless is_arr?
    return self.class.new(typename: @typename, pointer_level: @pointer_level, array_size: nil)
  end

  # Size of this type for a load/store"""
  def _mem_ins_size
    is_arr? ? as_non_array.sizeof : sizeof
  end

  def load_ins
    ["", "i32.load8_s", "i32.load16_s", "", "i32.load"][_mem_ins_size]
  end

  def store_ins
    ["", "i32.store8", "i32.store16", "", "i32.store"][_mem_ins_size]
  end

  def inspect
    arr = @array_size.nil? ? nil : "[#{@array_size}]"
    return "#{@typename}#{'*' * @pointer_level}#{arr}"
  end
end


$typedefs = {}

# Parse a type and variable name like `int** x[5]`. If `prev_t` is provided,
# it will be used instead of trying to eat a new type token from the lexer,
# to support parsing a type in a comma-separated declaration like `int x, *y;`.
# @return [Array<Ctype, Token>]
def parse_type_and_name(lexer, prev_t = nil)
  t = prev_t || lexer.next(TOK_TYPE).content
  ct = ($typedefs[t].&dup) || CType.new(typename: t)
  ct.decl_line = lexer.line
  type = ct

  while lexer.try_next("*") do
    type.pointer_level += 1
  end

  varname = lexer.next(TOK_NAME)
  if lexer.try_next("[")
    type.array_size = lexer.next(TOK_INTCONST).content.to_i
    lexer.next("]")
  end

  return [type, varname]
end

# Variable in a StackFrame.
# * `name`: name of the variable
# * `type`: the variable's type
# * `local_offset`: how many bytes from the top of this frame does the value start
# * `is_parameter`: whether the value is a parameter (True) or a local var (False)
FrameVar = Data.define(:name, :type, :local_offset, :is_parameter)

class StackFrame
  attr_reader :frame_size, :frame_offset, :variables

  def initialize(parent: nil)
    @parent = parent
    @variables = {}
    @frame_size = 0
    @frame_offset = parent ? parent.frame_offset + parent.frame_size : 0
  end

  def add_var(name, type, is_parameter = false)
    @variables[name] = FrameVar.new(name, type, @frame_size, is_parameter)
    @frame_size += type.sizeof()
  end

  def get_var_and_offset(name)
    n = name.is_a?(String) ? name : name.content
    if (slot = @variables[n])
      return [slot, @frame_offset + slot.local_offset]
    elsif !@parent.nil?
      return @parent.get_var_and_offset(name)
    else
      die("unknown variable #{name.is_a?(String) ? nil : name.line}")
    end
  end
end

def emit_return(frame)
  $emitter.emit("global.get $__stack_pointer ;; fixup stack pointer before return")
  $emitter.emit("i32.const #{frame.frame_size}")
  $emitter.emit("i32.add")
  $emitter.emit("global.set $__stack_pointer")
  $emitter.emit("return")
end

# Metadata returned after generating code for an expression.
# * `is_place`: whether the expression was a place or a bare value.
  # places are represented on the stack as an address, but not all addresses are
  # places--places are things that can be assigned to. for example x[5] is a place,
  # but &x is not. values are things that can be operated on, e.g. (x + 1) is a value
  # because (x + 1) = 2 is meaningless.
  # use `load_result` to turn a place into a value.
# * `type`: the type of the expression
ExprMeta = Data.define(:is_place, :type)

# Load a place `ExprMeta`, turning it into a value `ExprMeta` of the same type
def load_result(em)
  if em.is_place
    $emitter.emit(em.type.load_ins)
  end
  return ExprMeta.new(false, em.type)
end

# Mask an i32 down to the appropriate size after an operation
def mask_to_sizeof(t)
  if !(t.is_arr? || t.sizeof == 4)
    # bits = `8 * sizeof`, less one if the type is signed since that's in the high sign bit)
    $emitter.emit("i32.const #{hex(2 ** (8 * t.sizeof - t.signed) - 1)}")
    $emitter.emit(f"i32.and")
  end
end

class Expression

  attr_reader :lexer, :frame

  # function for generating simple operator precedence levels from declarative
  # dictionaries of { token: instruction_to_emit }
  def self.makeop(method_name, higher, ops, rtype = nil)
    define_method(method_name) do
      lhs_meta = send(higher)
      if ops.keys().map(&:to_s).include?(lexer.peek().kind.to_s)
        lhs_meta = load_result(lhs_meta)
        op_token = lexer.next()
        load_result(send(method_name))
        $emitter.emit("#{ops[op_token.kind.to_sym]}")
        mask_to_sizeof(rtype || lhs_meta.type)
        return ExprMeta.new(false, lhs_meta.type)
      end
      return lhs_meta
    end
  end

  def self.call(lexer, frame)
    new(lexer, frame).assign
  end

  def initialize(lexer, frame)
    @lexer = lexer
    @frame = frame
    self.class.makeop(:muldiv, :prefix, {"*": "i32.mul", "/": "i32.div_s", "%": "i32.rem_s"})
    self.class.makeop(:shlr, :plusminus, {"<<": "i32.shl", ">>": "i32.shr_s"})
    self.class.makeop(:cmplg, :shlr, {"<": "i32.lt_s", ">": "i32.gt_s", "<=": "i32.le_s", ">=": "i32.ge_s"}, CType.new(typename: "int"))
    self.class.makeop(:cmpe, :cmplg, {"==": "i32.eq", "!=": "i32.ne"}, CType.new(typename: "int"))
    self.class.makeop(:bitand, :cmpe, {"&": "i32.and"})
    self.class.makeop(:bitor, :bitand, {"|": "i32.or"})
    self.class.makeop(:xor, :bitor, {"^": "i32.xor"})
  end

  def assign
    lhs_meta = xor()
    if lexer.try_next("=")
      if !lhs_meta.is_place
        die("lhs of assignment cannot be value", lexer.line)
      end
      $emitter.emit("call $__dup_i32")  # save copy of addr for later
      rhs_meta = load_result(assign())

      $emitter.emit(lhs_meta.type.store_ins())
      # use the saved address to immediately reload the value
      # this is slower than saving the value we just wrote, but easier to codegen :-)
      # this is needed for expressions like x = (y = 1)
      $emitter.emit(lhs_meta.type.load_ins())
      return rhs_meta
    end
    return lhs_meta
  end

  def value
    if const = lexer.try_next(TOK_INTCONST)
      $emitter.emit("i32.const #{const.content}")
      return ExprMeta.new(false, CType.new(typename: "int"))
    elsif const = lexer.try_next(TOK_CHARCONST)
      # cursed, but it works
      $emitter.emit("i32.const #{ord(eval(const.content))}")
      # character constants are integers in c, not char
      return ExprMeta.new(false, CType.new(typename: "int"))
    elsif const = lexer.try_next(TOK_STRCONST)
      # i keep writing cursed code and it keeps working
      # TODO fix encoding for ruby
      s = eval(const.content).encode("ascii")
      # support pasting: `char* p = "abc" "def";`
      while const = lexer.try_next(TOK_STRCONST) do
        s += eval(const.content).encode("ascii")
      end
      $emitter.emit("i32.const #{$str_pool.add(s)}")
      return ExprMeta.new(false, CType.new("char", pointer_level: 1))
    elsif lexer.try_next("(")
      meta = Expression.call(lexer, frame)
      lexer.next(")")
      return meta
    else

      varname = lexer.next(TOK_NAME)
      # is this a function call?
      if lexer.try_next("(")
        # yes, parse the parameters (if any) and leave them on the operand stack
        if lexer.peek().kind != ")"
          loop do
            load_result(Expression.call(lexer, frame))
            if !lexer.try_next(",")
              break
            end
          end
        end
        lexer.next(")")
        # call the function
        $emitter.emit("call $#{varname.content}")
        return ExprMeta.new(false, CType.new(typename: "int")) # TODO return type
      else
        # no, it's a variable reference, fetch it
        var, offset = frame.get_var_and_offset(varname)
        $emitter.emit("global.get $__stack_pointer ;; load #{varname.content}")
        $emitter.emit("i32.const #{offset}")
        $emitter.emit("i32.add")
        return ExprMeta.new(true, var.type)
      end
    end
  end

  def accessor
    lhs_meta = value  # TODO: this is wrong for x[0][0], right?
    if lexer.try_next("[")
      lhs_meta = load_result(lhs_meta)
      l_type = lhs_meta.type

      if !(l_type.is_arr? || l_type.is_ptr?)
        die(f"not an array or pointer: {lhs_meta.type}", lexer.line)
      end

      el_type = l_type.is_arr? ? l_type.as_non_array() : l_type.less_ptr()

      load_result(expression(lexer, frame))
      lexer.next("]")
      $emitter.emit("i32.const #{el_type.sizeof()}")
      $emitter.emit("i32.mul")
      $emitter.emit("i32.add")
      return ExprMeta.new(true, el_type)
    else
      return lhs_meta
    end
  end
  
  def prefix
    if lexer.try_next("&")
      meta = prefix()
      if !meta.is_place
        die("cannot take reference to value", lexer.line)
      end
      return ExprMeta.new(false, meta.type.more_ptr())
    elsif lexer.try_next("*")
      meta = load_result(prefix())
      if !meta.type.is_ptr?
        die("cannot dereference non-pointer", lexer.line)
      end
      return ExprMeta.new(true, meta.type.less_ptr())
    elsif lexer.try_next("-")
      $emitter.emit("i32.const 0")
      meta = load_result(prefix())
      $emitter.emit("i32.sub")
      mask_to_sizeof(meta.type)
      return meta
    elsif lexer.try_next("+")
      return load_result(prefix())
    elsif lexer.try_next("!")
      meta = load_result(prefix())
      $emitter.emit("i32.eqz")
      return meta
    elsif lexer.try_next("~")
      meta = load_result(prefix())
      $emitter.emit("i32.const 0xffffffff")
      $emitter.emit("i32.xor")
      mask_to_sizeof(meta.type)
      return meta
    else
      return accessor
    end
  end

  def plusminus
    lhs_meta = muldiv

    if ["+", "-"].include?(lexer.peek().kind)
      lhs_meta = load_result(lhs_meta)
      op_token = lexer.next()
      rhs_meta = load_result(plusminus())

      lhs_type = lhs_meta.type
      rhs_type = rhs_meta.type
      res_type = lhs_meta.type
      
      # handle pointer math: `((int*)4) - 1 == (int*)0` because int is 4 bytes
      # (this makes for (char* c = arr; c < arr+size; c++) work)
      if lhs_meta.type.pointer_level == rhs_meta.type.pointer_level
        # TODO will handle this later
      elsif lhs_meta.type.is_ptr? and rhs_meta.type.is_ptr?
        die("cannot #{op_token.content} #{lhs_meta.type} and #{rhs_meta.type}")
      elsif lhs_meta.type.is_ptr? && !rhs_meta.type.is_ptr?
        # left hand side is pointer: multiply rhs by sizeof
        $emitter.emit("i32.const #{lhs_meta.type.less_ptr().sizeof()}")
        $emitter.emit("i32.mul")
      elsif !lhs_meta.type.is_ptr? && rhs_meta.type.is_ptr?
        # right hand side is pointer: juggle the stack to get rhs on top,
        # then multiply and juggle back
        res_type = rhs_meta.type
        $emitter.emit("call $__swap_i32")
        $emitter.emit("i32.const #{rhs_meta.type.less_ptr().sizeof()}")
        $emitter.emit("i32.mul")
        $emitter.emit("call $__swap_i32")
      end

      if op_token.kind == "+" 
        $emitter.emit("i32.add")
      else
        $emitter.emit("i32.sub")
      end

      if op_token.kind == "-" && lhs_type.is_ptr? && rhs_type.is_ptr?
        # handle pointer subtraction case we skipped before:
        # `((int*)8) - ((int*)4) == 1`, so we need to divide by sizeof
        # (we could use shl, but the webassembly engine will almost
        #  certainly do the strength reduction for us)
        $emitter.emit("i32.const #{rhs_meta.type.less_ptr().sizeof()}")
        $emitter.emit("i32.div_s")
        res_type = CType.new(typename: "int")
      end

      mask_to_sizeof(res_type)
      return ExprMeta.new(false, res_type)

    end

    return lhs_meta
  end

end

class Statement
  attr_reader :lexer, :frame

  def self.call(lexer, frame)
    new(lexer, frame).call
  end

  def initialize(lexer, frame)
    @lexer = lexer
    @frame = frame
  end

  def call
    if lexer.try_next("return")
      if lexer.peek.kind != ";"
        load_result(Expression.call(lexer, frame))
      end
      lexer.next(";")
      emit_return(frame)
    elsif lexer.try_next("if")
      # we emit two nested blocks:
      #
      # block
      #   block
      #     ;; if test
      #     br_if 0
      #     ;; if body
      #     br 1
      #   end
      #   ;; else body
      # end
      #
      # the first br_if 0 will conditionally jump to the end of the inner block
      # if the test results in `0`, running the `;; else body` code.
      # the second, unconditional `br 1` will jump to the end of the outer block,
      # skipping `;; else body` if `;; if body` already ran.
      $emitter.emit.block(start: "block ;; if statement", finish: "end") do
        $emitter.emit.block(start: "block", finish: "end") do
          parenthesized_test()
          $emitter.emit("br_if 0 ;; jump to else")
          bracketed_block_or_single_statement(lexer, frame)
          $emitter.emit("br 1 ;; exit if")  # skip to end of else block
        end
        if lexer.try_next("else")
          bracketed_block_or_single_statement(lexer, frame)
        end
      end
    elsif lexer.try_next("while")
      # we again emit two nested blocks, but one is a loop:
      #
      # block
      #   loop
      #     ;; test
      #     br_if 1
      #     ;; loop body
      #     br 0
      #   end
      # end
      #
      # `while` statements don't have else blocks, so this isn't for the same reason
      # as `if`. instead, it's because of how loop blocks work. a branch (br or br_if)
      # in a loop block jumps to the *beginning* of the block, not the end, so to exit
      # early we need an outer, regular block that we can jump to the end of.
      # `br_if 1` jumps to the end of that outer block if the test fails,
      # skipping the loop body.
      # `br 0` jumps back to the beginning of the loop to re-run the test if the loop
      # body finishes.
      $emitter.emit.block(start: "block ;; while", finish: "end") do
        $emitter.emit.block(start: "loop", finish: "end") do
          parenthesized_test()
          $emitter.emit("br_if 1 ;; exit loop")
          bracketed_block_or_single_statement(lexer, frame)
          $emitter.emit("br 0 ;; repeat loop")
        end
      end
    elsif lexer.try_next("do")
      # `do` is very similar to `while`, but the test is at the end instead.
      $emitter.emit.block(start: "block ;; do-while", finish: "end") do
        $emitter.emit.block(start: "loop", finish: "end") do
          bracketed_block_or_single_statement(lexer, frame)
          lexer.next("while")
          parenthesized_test()
          $emitter.emit("br_if 1 ;; exit loop")
          $emitter.emit("br 0 ;; repeat loop")
          lexer.next(";")
        end
      end
    elsif lexer.try_next("for")
      # for is the most complicated control structure. it's also the hardest to
      # deal with in our setup, because the third "advancement" statement (e.g. i++ in
      # a typical range loop) needs to be generated *after* the body, even though it
      # comes before. We'll handle this by relexing it, which I'll show in a second.
      # just like the while and do loop, we'll have two levels of blocks:
      #
      # block
      #   ;; for initializer
      #   drop ;; discard the result of the initializer
      #   loop
      #     ;; for test
      #     br_if 1
      #     ;; (we lex over the advancement statement here, but don't emit any code)
      #     ;; for body
      #     ;; for advancement (re-lexed)
      #     br 0
      #   end
      # end
      #
      # Just like in the `while` or `do`, we emit the test, `br_if` to the end of the outer block
      # if the test fails, and otherwise `br 0` to the beginning of the inner loop.
      # The differences are:
      # 1. We code for the initializer and to discard its value at the beginning of the block.
      #    This code only runs once, it's just grouped into the for block for ease of reading the
      #    WebAssembly.
      # 2. We have the for advancement statement emitted *after* the body. How?
      #    Right before lexing it the first time, we save a copy of the current lexer,
      #    including its position.
      #    Then, we disable `emit()` with the `no_emit` context manager and call `expression`.
      #    This will skip over the expression without emitting any code.
      #    Next, we lex and emit code for the body as usual.
      #    Finally, before parsing the closing curly brace for the for loop, we use the saved
      #    lexer to go over the advancement statement *again*, but this time emitting code.
      #    This places the code for the advancement statement in the right place.
      #    Perfect! All it took was some minor crimes against the god of clean code :-)
      lexer.next("(")
      $emitter.block(start: "block ;; for", finish: "end") do
        if lexer.peek.kind != ";"
          Expression.call(lexer, frame)
          $emitter.emit("drop ;; discard for initializer")
        end
        lexer.next(";")
        $emitter.block(start: "loop", finish: "end") do
          if lexer.peek().kind != ";"
            load_result(Expression.call(lexer, frame))
            $emitter.emit("i32.eqz ;; for test")
            $emitter.emit("br_if 1 ;; exit loop")
          end
          lexer.next(";")
          saved_lexer = nil
          if lexer.peek().kind != ")"
            # save lexer position to emit advance stmt later (nasty hack)
            saved_lexer = lexer.clone
            $emitter.no_emit() do
              Expression.call(lexer, frame)  # advance past expr
            end
          end
          lexer.next(")")
          $emitter.emit(";; for body")
          bracketed_block_or_single_statement(lexer, frame)
          if saved_lexer != nil
            $emitter.emit(";; for advancement")
            Expression.call(saved_lexer, frame)  # use saved lexer
          end
          $emitter.emit("br 0 ;; repeat loop")
        end
      end
    elsif lexer.try_next(";")
      # noop
    else
      Expression.call(lexer, frame)
      lexer.next(";")
      $emitter.emit("drop ;; discard statement expr result")
    end
  end

  private

  # Helper to parse a parenthesized condition like `(x == 1)`
  def parenthesized_test
    lexer.next("(")
    load_result(Expression.call(lexer, frame))
    lexer.next(")")
    $emitter.emit("i32.eqz")
  end

  # Helper to parse the block of a control flow statement
  def bracketed_block_or_single_statement(lexer, frame)
    if lexer.try_next("{")
      while !lexer.try_next("}")
        Statement.call(lexer, frame)
      end
    else
      Statement.call(lexer, frame)
    end
  end
end

def variable_declaration(lexer, frame)
  # parse a variable declaration like `int x, *y[2], **z`.
  # the only thing each element in that list shares is the typename.
  # adds each parsed variable to the provided stack frame.

  # we need to explicitly grab this in case it's a typedef--the return type will have
  # the resolved typename, so if get back `int*` we don't know if the decl was
  # `typedef int* foo; foo x, *y` or `int *x, *y` -- in the first case y should be `int**`,
  # but in the second it should be `int*`
  prev_typename = lexer.peek().content
  # however we don't use prev_typename for the first call, because we want parse_type_and_name to
  # still eat the typename
  type, varname = parse_type_and_name(lexer)
  frame.add_var(varname.content, type)

  while lexer.try_next(",") do
    type, varname = parse_type_and_name(lexer, prev_typename)
    frame.add_var(varname.content, type)
  end

  lexer.next(";")
end

def global_declaration(global_frame, lexer)
  # parse a global declaration -- typedef, global variable, or function.

  if lexer.try_next("typedef")
    # yes, `typedef int x[24];` is valid (but weird) c
    type, name = parse_type_and_name(lexer)
    # lexer hack!
    lexer.types.add(name.content)
    $typedefs[name.content] = type

    lexer.next(";")
    return
  end

  decl_type, name = parse_type_and_name(lexer)

  if lexer.try_next(";")
    # variable declaration
    global_frame.add_var(name.content, decl_type, false)
    return
  end

  # otherwise, we're declaring a function (or, there's an = sign and this is
  # a global array initialization, which we don't support)
  if decl_type.is_arr?
    die("function array return / global array initializer not supported")
  end

  frame = StackFrame.new(parent: global_frame)
  lexer.next("(")
  while !lexer.try_next(")") do
    type, varname = parse_type_and_name(lexer)
    frame.add_var(varname.content, type, true)
    if lexer.peek().kind != ")"
      lexer.try_next(",")
    end
  end

  lexer.next("{")
  # declarations (up top, c89 only yolo)
  while lexer.peek().kind == TOK_TYPE do
    variable_declaration(lexer, frame)
  end

  $emitter.block(start: "(func $#{name.content}", finish: ")") do
    frame.variables.values.each do |v|
      if v.is_parameter
        $emitter.emit("(param $#{v.name} #{v.type.wasmtype})")
      end
    end
    $emitter.emit("(result #{decl_type.wasmtype})")
    $emitter.emit("global.get $__stack_pointer ;; prelude -- adjust stack pointer")
    $emitter.emit("i32.const #{frame.frame_offset + frame.frame_size}")
    $emitter.emit("i32.sub")
    $emitter.emit("global.set $__stack_pointer")
    frame.variables.values().reverse.each do |v|
      if v.is_parameter
        $emitter.emit("global.get $__stack_pointer ;; prelude -- setup parameter")
        $emitter.emit("i32.const #{frame.get_var_and_offset(v.name)[1]}")
        $emitter.emit("i32.add")
        $emitter.emit("local.get $#{v.name}")
        $emitter.emit(v.type.store_ins())
      end
    end

    while !lexer.try_next("}") do
      Statement.call(lexer, frame)
    end

    $emitter.emit("unreachable")
    # TODO: for void functions we need to add an addl emit_return for implicit returns
  end
end

def compile(src)
  # compile an entire file

  $emitter.block(start: "(module", finish: ")") do
    $emitter.emit("(memory 3)")
    $emitter.emit("(global $__stack_pointer (mut i32) (i32.const #{PAGE_SIZE * 3}))")
    $emitter.emit("(func $__dup_i32 (param i32) (result i32 i32)")
    $emitter.emit("  (local.get 0) (local.get 0))")
    $emitter.emit("(func $__swap_i32 (param i32) (param i32) (result i32 i32)")
    $emitter.emit("  (local.get 1) (local.get 0))")

    global_frame = StackFrame.new
    lexer = Lexer.new(src: src, types: Set.new(["int", "char", "short", "long", "float", "double"]))
    while lexer.peek().kind != TOK_EOF do
      global_declaration(global_frame, lexer)
    end

    $emitter.emit('(export "main" (func $main))')

    # emit str_pool data section
    $emitter.emit("(data $.rodata (i32.const #{$str_pool.base}) \"#{$str_pool.pooled()}\")")
  end
end

path = ARGV[0]
s = File.read(path)
compile(s)
