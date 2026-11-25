"""统一错误类型：带一句可执行的修复建议。"""


class ReError(Exception):
    """命令失败时抛这个。hint 是给人看的下一步，不是堆栈。"""

    def __init__(self, message: str, hint: str | None = None, code: int = 1):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.code = code
