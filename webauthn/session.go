package webauthn

// Session will be used by the request handlers to save temporary data, such as the challenge and user ID.
type Session interface {
	Set(name string, value string) error
	Get(name string) (string, error)
	Delete(name string) error
}

var _ Session = (*mapSession)(nil)

type mapSession struct {
	Values map[string]string
}

func (s *mapSession) Get(name string) (string, error) {
	return s.Values[name], nil
}

func (s *mapSession) Set(name string, value string) error {
	s.Values[name] = value
	return nil
}

func (s *mapSession) Delete(name string) error {
	delete(s.Values, name)
	return nil
}

// WrapMap can be used to create a Session for e.g. a gorilla/sessions type.
func WrapMap(values map[string]string) Session {
	return &mapSession{values}
}
