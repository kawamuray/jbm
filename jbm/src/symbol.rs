use crate::Result;
use blazesym::symbolize::{Process, Source, SymbolizedResult, Symbolizer};

pub(crate) struct Resolver {
    symbolizer: Symbolizer,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            symbolizer: Symbolizer::new(),
        }
    }

    pub fn resolve(&self, pid: u32, stack: &[usize]) -> Result<Vec<(u64, Option<String>)>> {
        let src = Source::Process(Process::new(pid.into()));
        let symbols = self.symbolizer.symbolize(&src, stack)?;

        let mut result = Vec::with_capacity(stack.len());
        for (i, address) in stack.iter().enumerate() {
            if symbols.len() <= i || symbols[i].is_empty() {
                result.push((*address as u64, None));
                continue;
            }

            let SymbolizedResult {
                symbol,
                addr: _,
                path,
                line,
                column: _,
            } = &symbols[i][0];
            let symbol = format!("{symbol}@{}:{line}", path.display());
            result.push((*address as u64, Some(symbol)));
        }
        Ok(result)
    }
}
