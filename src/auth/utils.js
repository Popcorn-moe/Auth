export const callbackify = (verify) => 
        (...args) => 
            verify(...args.slice(0, -1))
                .then(r => args[args.length - 1](null, r), e => args[args.length - 1](e))
                