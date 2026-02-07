pub(crate) trait Embedding {
    type Source;
    type Target;

    fn map(&self, value: Self::Source) -> Self::Target;
}
